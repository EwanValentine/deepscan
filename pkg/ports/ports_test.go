package ports

import "testing"

func TestConvertPortRange(t *testing.T) {
	tcs := []struct {
		name      string
		input     string
		wantStart uint32
		wantEnd   uint32
		wantErr   bool
	}{
		{"empty", "", 0, 0, true},
		{"full range", "8080:9090", 8080, 9090, false},
		{"single port", "8080", 0, 0, true},
		{"no end", "8080:", 0, 0, true},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			start, end, err := ConvertPortRange(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, want to have error = %t", err, tc.wantErr)
			}
			if start != tc.wantStart {
				t.Errorf("start = %d, want %d", start, tc.wantStart)
			}
			if end != tc.wantEnd {
				t.Errorf("end = %d, want %d", end, tc.wantEnd)
			}
		})
	}
}
