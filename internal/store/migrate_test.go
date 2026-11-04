package store

import (
	"slices"
	"testing"
	"testing/fstest"
)

func TestParseFiles(t *testing.T) {
	file := func(sql string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(sql)} }

	tests := []struct {
		name     string
		fsys     fstest.MapFS
		versions []int64
		wantErr  bool
	}{
		{
			name:     "empty",
			fsys:     fstest.MapFS{},
			versions: []int64{},
		},
		{
			name: "sorted by number, not by name",
			fsys: fstest.MapFS{
				"10_j.sql": file("j"), "9_i.sql": file("i"), "8_h.sql": file("h"),
				"7_g.sql": file("g"), "6_f.sql": file("f"), "5_e.sql": file("e"),
				"4_d.sql": file("d"), "3_c.sql": file("c"), "2_b.sql": file("b"),
				"1_a.sql": file("a"),
			},
			versions: []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		{
			name: "padded",
			fsys: fstest.MapFS{
				"0001_init.sql": file("a"),
				"0002_next.sql": file("b"),
			},
			versions: []int64{1, 2},
		},
		{
			name: "non-sql files and dirs are skipped",
			fsys: fstest.MapFS{
				"0001_init.sql":     file("a"),
				"README.md":         file("readme"),
				"embed.go":          file("package x"),
				"old/0002_x.sql":    file("nested"),
				"0002_next.sql.bak": file("backup"),
			},
			versions: []int64{1},
		},
		{
			name:    "gap",
			fsys:    fstest.MapFS{"0001_a.sql": file("a"), "0003_c.sql": file("c")},
			wantErr: true,
		},
		{
			name:    "does not start with 1",
			fsys:    fstest.MapFS{"0002_b.sql": file("b")},
			wantErr: true,
		},
		{
			name:    "zero",
			fsys:    fstest.MapFS{"0000_zero.sql": file("z"), "0001_a.sql": file("a")},
			wantErr: true,
		},
		{
			name:    "duplicate",
			fsys:    fstest.MapFS{"0001_a.sql": file("a"), "01_b.sql": file("b")},
			wantErr: true,
		},
		{
			name:    "no underscore",
			fsys:    fstest.MapFS{"0001.sql": file("a")},
			wantErr: true,
		},
		{
			name:    "not a number",
			fsys:    fstest.MapFS{"init_0001.sql": file("a")},
			wantErr: true,
		},
		{
			name:    "negative",
			fsys:    fstest.MapFS{"-1_a.sql": file("a")},
			wantErr: true,
		},
		{
			name:    "plus sign",
			fsys:    fstest.MapFS{"+1_a.sql": file("a")},
			wantErr: true,
		},
		{
			name:    "empty version",
			fsys:    fstest.MapFS{"_a.sql": file("a")},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms, err := parseFiles(tt.fsys)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseFiles() err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			versions := make([]int64, 0, len(ms))
			for _, m := range ms {
				versions = append(versions, m.version)
			}
			if !slices.Equal(versions, tt.versions) {
				t.Errorf("parseFiles() versions = %v, want %v", versions, tt.versions)
			}
		})
	}
}

func TestParseFilesContent(t *testing.T) {
	ms, err := parseFiles(fstest.MapFS{
		"0001_init.sql": &fstest.MapFile{Data: []byte("create table t ();")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("len = %d, want 1", len(ms))
	}
	if ms[0].name != "0001_init.sql" || ms[0].sql != "create table t ();" {
		t.Errorf("got %+v", ms[0])
	}
}

func TestPendingMigrations(t *testing.T) {
	ms := []migration{{version: 1}, {version: 2}, {version: 3}}

	tests := []struct {
		name    string
		applied []int64
		pending []int64
		wantErr bool
	}{
		{name: "fresh database", applied: nil, pending: []int64{1, 2, 3}},
		{name: "partially applied", applied: []int64{1, 2}, pending: []int64{3}},
		{name: "up to date", applied: []int64{1, 2, 3}, pending: []int64{}},
		{name: "database ahead of files", applied: []int64{1, 2, 3, 4}, wantErr: true},
		{name: "gap in applied", applied: []int64{1, 3}, wantErr: true},
		{name: "applied does not start with 1", applied: []int64{2}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pending, err := pendingMigrations(ms, tt.applied)
			if (err != nil) != tt.wantErr {
				t.Fatalf("pendingMigrations() err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			versions := make([]int64, 0, len(pending))
			for _, m := range pending {
				versions = append(versions, m.version)
			}
			if !slices.Equal(versions, tt.pending) {
				t.Errorf("pendingMigrations() versions = %v, want %v", versions, tt.pending)
			}
		})
	}
}
