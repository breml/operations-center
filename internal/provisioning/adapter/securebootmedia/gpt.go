package securebootmedia

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"unicode/utf16"

	"github.com/google/uuid"
)

const (
	// isoBlockSize is the logical block size of the generated image. A BMC
	// presents the image as a CD, which is read in 2048 byte blocks, so the
	// partition table has to be laid out for that block size to be found.
	isoBlockSize = 2048

	// gptEntryCount and gptEntrySize are the minimum a GPT has to provide.
	gptEntryCount = 128
	gptEntrySize  = 128

	// gptEntryBlocks is the number of blocks the partition entry array occupies.
	gptEntryBlocks = gptEntryCount * gptEntrySize / isoBlockSize

	// gptHeaderSize is the size of the used part of a GPT header.
	gptHeaderSize = 92

	// espStartLBA is the block the EFI system partition starts at. It leaves
	// room for the primary GPT and aligns the partition to 32 KiB.
	espStartLBA = 16

	// mbrSize is the size of the protective master boot record.
	mbrSize = 512
)

// espTypeGUID is the partition type of an EFI system partition.
const espTypeGUID = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"

// espPartitionName is the label of the EFI system partition of the enrollment
// media.
const espPartitionName = "ESP"

// writeISO writes the enrollment media, an EFI system partition holding esp
// wrapped in a GPT laid out for 2048 byte blocks, to w.
//
// diskGUID and partitionGUID are provided by the caller, so that the very same
// input produces the very same image.
func writeISO(w io.Writer, esp io.Reader, espSize int64, diskGUID uuid.UUID, partitionGUID uuid.UUID) error {
	if espSize <= 0 {
		return fmt.Errorf("Invalid EFI system partition size %d", espSize)
	}

	espBlocks := (espSize + isoBlockSize - 1) / isoBlockSize
	espEndLBA := espStartLBA + espBlocks - 1

	// The backup partition entry array and the backup header follow the
	// partition, so the last usable block is the last block of the partition.
	lastLBA := espEndLBA + gptEntryBlocks + 1
	blockCount := lastLBA + 1

	layout := gptLayout{
		blockCount:     blockCount,
		firstUsableLBA: 2 + gptEntryBlocks,
		lastUsableLBA:  espEndLBA,
		espStartLBA:    espStartLBA,
		espEndLBA:      espEndLBA,
		diskGUID:       diskGUID,
		partitionGUID:  partitionGUID,
	}

	entries := layout.entryArray()
	entriesCRC := crc32.ChecksumIEEE(entries)

	// Block 0 holds the protective MBR.
	block := make([]byte, isoBlockSize)
	copy(block, layout.protectiveMBR())

	err := writeAll(w, block)
	if err != nil {
		return err
	}

	// Block 1 holds the primary header, blocks 2 and up the partition entries.
	err = writeBlock(w, layout.header(1, lastLBA, 2, entriesCRC))
	if err != nil {
		return err
	}

	err = writeAll(w, entries)
	if err != nil {
		return err
	}

	// Pad up to the start of the partition.
	err = writeZeros(w, (espStartLBA-int64(2+gptEntryBlocks))*isoBlockSize)
	if err != nil {
		return err
	}

	written, err := io.Copy(w, esp)
	if err != nil {
		return fmt.Errorf("Failed to write the EFI system partition: %w", err)
	}

	if written != espSize {
		return fmt.Errorf("EFI system partition is %d bytes instead of the announced %d", written, espSize)
	}

	err = writeZeros(w, espBlocks*isoBlockSize-espSize)
	if err != nil {
		return err
	}

	// The backup partition entries and the backup header close the image.
	err = writeAll(w, entries)
	if err != nil {
		return err
	}

	return writeBlock(w, layout.header(lastLBA, 1, espEndLBA+1, entriesCRC))
}

// gptLayout holds the block addresses the two GPT headers and the partition
// entry array are built from.
type gptLayout struct {
	blockCount     int64
	firstUsableLBA int64
	lastUsableLBA  int64
	espStartLBA    int64
	espEndLBA      int64
	diskGUID       uuid.UUID
	partitionGUID  uuid.UUID
}

// protectiveMBR returns the master boot record, that makes a tool, which does
// not know about GPT, see a single partition spanning the whole image instead
// of unpartitioned space.
func (l gptLayout) protectiveMBR() []byte {
	mbr := make([]byte, mbrSize)

	entry := mbr[446:462]
	entry[0] = 0x00                                 // Not bootable.
	entry[1], entry[2], entry[3] = 0x00, 0x02, 0x00 // Start CHS, the smallest possible address.
	entry[4] = 0xEE                                 // GPT protective.
	entry[5], entry[6], entry[7] = 0xFF, 0xFF, 0xFF // End CHS, saturated.
	binary.LittleEndian.PutUint32(entry[8:12], 1)   // First block of the GPT.
	binary.LittleEndian.PutUint32(entry[12:16], protectiveSize(l.blockCount))

	mbr[510], mbr[511] = 0x55, 0xAA

	return mbr
}

// protectiveSize is the number of blocks the protective partition covers,
// saturated at what its 32 bit field can hold.
func protectiveSize(blockCount int64) uint32 {
	blocks := blockCount - 1
	if blocks > 0xFFFFFFFF {
		return 0xFFFFFFFF
	}

	return uint32(blocks)
}

// header returns one of the two GPT headers, padded to a full block.
func (l gptLayout) header(myLBA int64, alternateLBA int64, entryLBA int64, entriesCRC uint32) []byte {
	block := make([]byte, isoBlockSize)
	header := block[:gptHeaderSize]

	copy(header[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000) // Revision 1.0.
	binary.LittleEndian.PutUint32(header[12:16], gptHeaderSize)
	// header[16:20] holds the header CRC, which is calculated below.
	binary.LittleEndian.PutUint64(header[24:32], uint64(myLBA))
	binary.LittleEndian.PutUint64(header[32:40], uint64(alternateLBA))
	binary.LittleEndian.PutUint64(header[40:48], uint64(l.firstUsableLBA))
	binary.LittleEndian.PutUint64(header[48:56], uint64(l.lastUsableLBA))
	copy(header[56:72], encodeGUID(l.diskGUID))
	binary.LittleEndian.PutUint64(header[72:80], uint64(entryLBA))
	binary.LittleEndian.PutUint32(header[80:84], gptEntryCount)
	binary.LittleEndian.PutUint32(header[84:88], gptEntrySize)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)

	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header))

	return block
}

// entryArray returns the partition entry array, holding the single EFI system
// partition of the enrollment media.
func (l gptLayout) entryArray() []byte {
	entries := make([]byte, gptEntryCount*gptEntrySize)
	entry := entries[:gptEntrySize]

	copy(entry[0:16], encodeGUID(uuid.MustParse(espTypeGUID)))
	copy(entry[16:32], encodeGUID(l.partitionGUID))
	binary.LittleEndian.PutUint64(entry[32:40], uint64(l.espStartLBA))
	binary.LittleEndian.PutUint64(entry[40:48], uint64(l.espEndLBA))
	copy(entry[56:128], encodePartitionName(espPartitionName))

	return entries
}

// encodeGUID returns the mixed endian encoding a GUID has on disk, where the
// first three fields are little endian and the rest is not.
func encodeGUID(id uuid.UUID) []byte {
	encoded := make([]byte, 16)
	copy(encoded, id[:])

	encoded[0], encoded[1], encoded[2], encoded[3] = id[3], id[2], id[1], id[0]
	encoded[4], encoded[5] = id[5], id[4]
	encoded[6], encoded[7] = id[7], id[6]

	return encoded
}

// encodePartitionName returns the null terminated UTF-16 encoding of a
// partition name, truncated to what the entry holds.
func encodePartitionName(name string) []byte {
	encoded := make([]byte, 72)

	for i, point := range utf16.Encode([]rune(name)) {
		offset := i * 2
		if offset+2 > len(encoded)-2 {
			break
		}

		binary.LittleEndian.PutUint16(encoded[offset:offset+2], point)
	}

	return encoded
}

func writeBlock(w io.Writer, block []byte) error {
	if len(block) != isoBlockSize {
		return fmt.Errorf("Invalid block size %d", len(block))
	}

	return writeAll(w, block)
}

func writeAll(w io.Writer, body []byte) error {
	_, err := w.Write(body)
	if err != nil {
		return fmt.Errorf("Failed to write the secure boot enrollment media: %w", err)
	}

	return nil
}

func writeZeros(w io.Writer, count int64) error {
	if count <= 0 {
		return nil
	}

	_, err := io.CopyN(w, zeroReader{}, count)
	if err != nil {
		return fmt.Errorf("Failed to write the secure boot enrollment media: %w", err)
	}

	return nil
}

// zeroReader is an endless source of zero bytes, used to pad the image.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)

	return len(p), nil
}
