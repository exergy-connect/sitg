package wire

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"testing"
)

func TestUETRejectTruncation(t *testing.T) {
	for _, b := range [][]byte{EncodeUETData(1, 1, 1, 0, 3, false, []byte("abc")), EncodeUETSACK(1, 3, 5)} {
		min := len(b)
		if b[0]>>3 == UETTypeData {
			min -= 3
		}
		for n := 0; n < min; n++ {
			if _, err := DecodeUETTransport(b[:n]); err == nil {
				t.Fatalf("accepted %d-byte header", n)
			}
		}
	}
}

func TestUETPcapView(t *testing.T) {
	path := os.Getenv("SITG_PCAP_VIEW")
	if path == "" {
		t.Skip("set SITG_PCAP_VIEW to pcap-view checkout")
	}
	script := `import {dissectUet} from 'file://` + path + `/dissectors/uet.js';
 import assert from 'node:assert/strict';
 const b=new Uint8Array(Buffer.from(process.argv[1], 'hex'));
 const d=dissectUet(b,{protocol:'UDP'});
 assert.equal(d.error,undefined,JSON.stringify(d));
 assert.equal(d.pds.type,Number(process.argv[2]));
 if(d.ses){assert.equal(d.ses.name,'Write');assert.equal(d.ses.messageId,9);assert.equal(d.payloadPreview,'61 62 63');}
 `
	for _, b := range [][]byte{EncodeUETData(42, 7, 9, 0, 3, true, []byte("abc")), EncodeUETData(43, 7, 9, 3, 6, false, []byte("abc")), EncodeUETSACK(7, 42, 11)} {
		out, err := exec.Command("node", "--input-type=module", "-e", script, hex.EncodeToString(b), fmt.Sprint(b[0]>>3)).CombinedOutput()
		if err != nil {
			t.Fatalf("pcap-view: %v %s", err, out)
		}
	}
}

func TestUETACKWireFields(t *testing.T) {
	for cum := uint32(0); cum < 16; cum++ {
		b := EncodeUETSACK(7, cum, 0xb)
		if got := binary.BigEndian.Uint32(b[4:]); got != cum-1 {
			t.Fatalf("CACK must be inclusive: %d", got)
		}
		base := cum - 1 + uint32(int32(int16(binary.BigEndian.Uint16(b[14:]))))
		if base&7 != 0 {
			t.Fatalf("unaligned SACK base %d", base)
		}
		f, err := DecodeUETTransport(b)
		if err != nil || f.CumAck != cum || f.Bitmap != 0xb {
			t.Fatalf("ACK translation: %+v %v", f, err)
		}
	}
}
