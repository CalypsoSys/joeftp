package joeftp

import "testing"

func TestParseExtendedPassivePort(t *testing.T) {
	tests := []struct {
		name    string
		msg     string
		port    int
		wantErr bool
	}{
		{
			name:    "canonical pipe delimiter",
			msg:     "229 Entering Extended Passive Mode (|||12345|)\r\n",
			port:    12345,
			wantErr: false,
		},
		{
			name:    "arbitrary delimiter from production log",
			msg:     "229 Entering Extended Passive Mode (!!!11823!).\r\n",
			port:    11823,
			wantErr: false,
		},
		{
			name:    "reject inconsistent delimiters",
			msg:     "229 Entering Extended Passive Mode (!|!11823!).\r\n",
			wantErr: true,
		},
		{
			name:    "reject digit delimiter",
			msg:     "229 Entering Extended Passive Mode (111118231)\r\n",
			wantErr: true,
		},
		{
			name:    "reject missing port",
			msg:     "229 Entering Extended Passive Mode (!!!!)\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, err := parseExtendedPassivePort(tt.msg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got port %d", port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if port != tt.port {
				t.Fatalf("port = %d, want %d", port, tt.port)
			}
		})
	}
}
