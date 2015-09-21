package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func add_padding(msg_slice []byte, key_len int) []byte {
	var msg_len_bits uint64 = uint64((len(msg_slice) + key_len) * 8)
	msg_slice = append(msg_slice, 0x80)
	// pad until the number of bits mod 512 is 448
	for ((len(msg_slice)+key_len)*8)%512 != 448 {
		msg_slice = append(msg_slice, 0x00)
	}
	// add original bit length as 64 bit bigendian int
	for i := uint(0); i < 8; i++ {
		var b byte
		// bitshift to the correct byte, and trucate to a byte size
		b = byte(msg_len_bits >> (56 - (i * 8)))
		msg_slice = append(msg_slice, b)
	}
	return msg_slice
}

func left_rotate(block uint32, amount uint) uint32 {
	block = ((block << amount) | (block >> (32 - amount))) & 0xffffffff
	return block
}

func b_to_i(block []byte) uint32 {
	return (uint32(block[0]) << 24) | (uint32(block[1]) << 16) | (uint32(block[2]) << 8) | uint32(block[3])
}

func i_to_b(i uint32) []byte {
	block := make([]byte, 4)
	block[0] = byte(i >> 24)
	block[1] = byte(i >> 16)
	block[2] = byte(i >> 8)
	block[3] = byte(i)
	return block
}

func hash_block(block, old_hash []byte, other_len int) []byte {
	// Pad the block
	// The total length at the end needs to show the whole message, so set keylen to the length of the message before the extension
	block = add_padding(block, other_len)
	// split up old_hash
	a := b_to_i(old_hash[0:4])
	b := b_to_i(old_hash[4:8])
	c := b_to_i(old_hash[8:12])
	d := b_to_i(old_hash[12:16])
	e := b_to_i(old_hash[16:20])

	w := make([]uint32, 80)
	// break block 16 32 bit words
	for i := 0; i < 16; i++ {
		w[i] = b_to_i(block[i*4 : (i+1)*4])
	}
	// extend to 80 32 bit words
	for i := 16; i < 80; i++ {
		w[i] = left_rotate(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
	}

	// do the operations
	for i := 0; i < 80; i++ {
		var k uint32
		var f uint32
		if i < 20 {
			f = (b & c) | ((^b) & d)
			k = 0x5A827999
		} else if i < 40 {
			f = b ^ c ^ d
			k = 0x6ED9EBA1
		} else if i < 60 {
			f = (b & c) | (b & d) | (c & d)
			k = 0x8F1BBCDC
		} else if i < 80 {
			f = b ^ c ^ d
			k = 0xCA62C1D6
		}

		a, b, c, d, e = (left_rotate(a, 5) + f + e + k + w[i]), a, left_rotate(b, 30), c, d
	}

	//Add to the old hash
	h0 := (b_to_i(old_hash[0:4]) + a) & 0xffffffff
	h1 := (b_to_i(old_hash[4:8]) + b) & 0xffffffff
	h2 := (b_to_i(old_hash[8:12]) + c) & 0xffffffff
	h3 := (b_to_i(old_hash[12:16]) + d) & 0xffffffff
	h4 := (b_to_i(old_hash[16:20]) + e) & 0xffffffff

	result := append(i_to_b(h0), i_to_b(h1)...)
	result = append(result, i_to_b(h2)...)
	result = append(result, i_to_b(h3)...)
	result = append(result, i_to_b(h4)...)
	return result
}

// So here is what you do
// given key length and a message, pad it like SHA1 would if there was a key on front
// You need a custom SHA1 thing, because you need to run the SHA on the last (new) block with the old Hash as the IV
func main() {
	if len(os.Args) <= 3 {
		fmt.Printf("Usage: %s <Key Length> \"<Original Message>\" \"<Original Hash hex>\" \"<Extension>\"\n", os.Args[0])
		fmt.Println("       Original Hash should be a 20 byte SHA-1 hash, that has been base64'd")
		fmt.Println("       Extension should be less than 64 bytes long")
		return
	}
	key_len, err := strconv.Atoi(os.Args[1])
	check(err)

	msg_slice := []byte(os.Args[2])
	old_hash, err := hex.DecodeString(os.Args[3])
	check(err)
	extension := []byte(os.Args[4])

	// Pad message as it would have been padded
	msg_slice = add_padding(msg_slice, key_len)
	length_b4_extension := len(msg_slice) + key_len
	// Append the Extension
	msg_slice = append(msg_slice, extension...)
	// Run it through a round of SHA1, with the old hash as the IV
	hash := hash_block(extension, old_hash, length_b4_extension)

	fmt.Printf("Message in hex:\n%s\nDigest in hex:\n%s\n", hex.EncodeToString(msg_slice), hex.EncodeToString(hash))
}
