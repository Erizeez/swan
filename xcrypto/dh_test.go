package xcrypto

import (
	"bytes"
	"testing"
)

func TestDHKeyExchange(t *testing.T) {
	groups := []uint16{
		TransformDHCurve25519,
		TransformDHMODP1024,
		TransformDHMODP2048,
	}

	for _, g := range groups {
		t.Run(formatGroupName(g), func(t *testing.T) {
			alice, err := GenerateDH(g)
			if err != nil {
				t.Fatalf("Alice GenerateDH(%d) failed: %v", g, err)
			}
			bob, err := GenerateDH(g)
			if err != nil {
				t.Fatalf("Bob GenerateDH(%d) failed: %v", g, err)
			}

			alicePub, err := alice.PublicBytes()
			if err != nil {
				t.Fatalf("Alice PublicBytes: %v", err)
			}
			bobPub, err := bob.PublicBytes()
			if err != nil {
				t.Fatalf("Bob PublicBytes: %v", err)
			}

			switch g {
			case TransformDHCurve25519:
				if len(alicePub) != 32 || len(bobPub) != 32 {
					t.Fatalf("unexpected pub length: %d, %d", len(alicePub), len(bobPub))
				}
			case TransformDHMODP1024:
				if len(alicePub) != 128 || len(bobPub) != 128 {
					t.Fatalf("unexpected pub length: %d, %d", len(alicePub), len(bobPub))
				}
			case TransformDHMODP2048:
				if len(alicePub) != 256 || len(bobPub) != 256 {
					t.Fatalf("unexpected pub length: %d, %d", len(alicePub), len(bobPub))
				}
			}

			aliceSecret, err := alice.ECDH(bobPub)
			if err != nil {
				t.Fatalf("Alice ECDH: %v", err)
			}
			bobSecret, err := bob.ECDH(alicePub)
			if err != nil {
				t.Fatalf("Bob ECDH: %v", err)
			}

			if !bytes.Equal(aliceSecret, bobSecret) {
				t.Fatalf("shared secrets do not match!\nAlice: %x\nBob:   %x", aliceSecret, bobSecret)
			}

			// Key reuse should fail
			if _, err := alice.ECDH(bobPub); err == nil {
				t.Errorf("Alice reuse ECDH succeeded, expected error")
			}
			if _, err := alice.PublicBytes(); err == nil {
				t.Errorf("Alice reuse PublicBytes succeeded, expected error")
			}
		})
	}
}

func TestProposalParsing_MODP(t *testing.T) {
	cases := []struct {
		propStr string
		wantDH  uint16
	}{
		{"aes128-sha1-modp1024", TransformDHMODP1024},
		{"aes128-sha1-dh2", TransformDHMODP1024},
		{"aes128-sha1-group2", TransformDHMODP1024},
		{"aes256gcm16-prfsha256-modp2048", TransformDHMODP2048},
		{"aes256gcm16-prfsha256-dh14", TransformDHMODP2048},
		{"aes256gcm16-prfsha256-group14", TransformDHMODP2048},
	}

	for _, tc := range cases {
		p, err := ParseProposal(tc.propStr)
		if err != nil {
			t.Fatalf("ParseProposal(%q) failed: %v", tc.propStr, err)
		}
		if len(p.DH) != 1 || p.DH[0] != tc.wantDH {
			t.Errorf("ParseProposal(%q) DH = %v, want [%d]", tc.propStr, p.DH, tc.wantDH)
		}

		sel, err := p.Select(&p)
		if err != nil {
			t.Fatalf("Select failed: %v", err)
		}
		if sel.DH == nil || sel.DH.TransformID != tc.wantDH {
			t.Errorf("Select DH = %v, want %d", sel.DH, tc.wantDH)
		}
	}
}

func formatGroupName(g uint16) string {
	switch g {
	case TransformDHCurve25519:
		return "Curve25519"
	case TransformDHMODP1024:
		return "MODP1024"
	case TransformDHMODP2048:
		return "MODP2048"
	default:
		return "Unknown"
	}
}
