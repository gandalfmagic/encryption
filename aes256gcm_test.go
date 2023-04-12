package encryption

import "testing"

func Test_aes256Cipher(t *testing.T) {
	type args struct {
		plaintext []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "lorem_ipsum",
			args:    args{plaintext: []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")},
			wantErr: false,
		},
		{
			name:    "simple_test",
			args:    args{plaintext: []byte("this is a test")},
			wantErr: false,
		},
		{
			name:    "empty",
			args:    args{plaintext: []byte{}},
			wantErr: false,
		},
		{
			name:    "nil",
			args:    args{plaintext: nil},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := NewAESCipher(testRandomString(32), "")
			encrypted, err := c.EncryptToHexString(tt.args.plaintext)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			plain, err := c.DecryptFromHexString(encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if string(plain) != string(tt.args.plaintext) {
				t.Errorf("Encrypt() got = %v, want %v", string(plain), tt.args.plaintext)
			}
		})
	}
}
