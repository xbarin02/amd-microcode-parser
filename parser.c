/**
 * Simple parser of AMD microcode blobs.
 *
 * David Barina <dabler@gmail.com>
 *
 * Sources:
 * - Linux kernel (arch/x86/kernel/cpu/microcode/{core,amd}.c)
 * - https://github.com/coreboot/coreboot/blob/master/src/cpu/amd/microcode/microcode.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define UCODE_MAGIC			0x00414d44
#define UCODE_EQUIV_CPU_TABLE_TYPE	0x00000000
#define UCODE_UCODE_TYPE		0x00000001

#define SECTION_HDR_SIZE		8
#define CONTAINER_HDR_SZ		12

struct equiv_cpu_entry {
	uint32_t	installed_cpu;
	uint32_t	fixed_errata_mask;
	uint32_t	fixed_errata_compare;
	uint16_t	equiv_cpu;
	uint16_t	res;
} __attribute__((packed));

struct section_header {
	uint32_t	start_of_section;
	uint32_t	size_of_microcode_section;
} __attribute__((packed));

struct microcode_header_amd {
	uint32_t	data_code;
	uint32_t	patch_id;
	uint16_t	mc_patch_data_id;
	uint8_t 	mc_patch_data_len;
	uint8_t 	init_flag;
	uint32_t	mc_patch_data_checksum;
	uint32_t	nb_dev_id;
	uint32_t	sb_dev_id;
	uint16_t	processor_rev_id;
	uint8_t 	nb_rev_id;
	uint8_t 	sb_rev_id;
	uint8_t 	bios_api_rev;
	uint8_t 	reserved1[3];
	uint32_t	match_reg[8];
} __attribute__((packed));

char *load_blob(const char *path, size_t *size)
{
	FILE *file = fopen(path, "r");

	if( !file ) {
		if( size )
			*size = 0;
		return NULL;
	}

	char *blob = NULL;
	size_t asize = 0, rsize = 0;

	while(1) {
		asize += 4096;
		blob = realloc(blob, asize);
		size_t bsize = fread(blob + rsize, 1, 4096, file);
		rsize += bsize;
		if( bsize < 4096 ) {
			break;
		}
	}

	fclose(file);

	if(size)
		*size = rsize;

	return blob;
}

size_t dump_equiv_id(struct equiv_cpu_entry *equiv_table)
{
	int i = 0;
	for(; equiv_table && equiv_table->installed_cpu; equiv_table++) {
		printf("\t [%i] found sig=0x%08x equiv_id=0x%04x\n", i, equiv_table->installed_cpu, equiv_table->equiv_cpu);
		i++;
	}

	// +1 due to the last zero record
	return (i + 1) * sizeof(struct equiv_cpu_entry);
}

size_t parse_blob(const char *blob, size_t size)
{
	if( size < CONTAINER_HDR_SZ ) {
		return 0;
	}

	const char *start = blob;

	// Container Header
	printf("Container Header:\n");

	uint32_t *hdr = (uint32_t *)blob;

	if( hdr[0] != UCODE_MAGIC || hdr[1] != UCODE_EQUIV_CPU_TABLE_TYPE || hdr[2] == 0 ) {
		return CONTAINER_HDR_SZ;
	}

	uint32_t n = hdr[2];
	printf("\t size of variable portion of container header = %u bytes\n", n);

	printf("\t header parsed\n");

	blob += CONTAINER_HDR_SZ;

	// table: the equivalence ID
	printf("Equivalence ID:\n");

	struct equiv_cpu_entry *eq = (struct equiv_cpu_entry *)(blob);

	size_t sizeof_equiv_id_table = dump_equiv_id(eq);
	printf("\t size of table = %zu\n", sizeof_equiv_id_table);

	blob += sizeof_equiv_id_table;

	if( start + CONTAINER_HDR_SZ + n == blob )
		printf("\t no extra padding :)\n");
	else
		printf("\t some extra padding is present :/\n");

	// skip the unknown padding
	blob = start + CONTAINER_HDR_SZ + n;

	while( (size_t)(blob - start) < size ) {
		// SECTION HEADER
		printf("Section header:\n");

		struct section_header *sh = (struct section_header *)blob;

		printf("\t Unique identifier signaling start of section = 0x%08x\n", sh->start_of_section);

		if( sh->start_of_section != UCODE_UCODE_TYPE ) {
			printf("\t unexpected data, breaking...\n");
			break;
		}

		uint32_t m = sh->size_of_microcode_section;
		printf("\t size of microcode section (including microcode header) = %u bytes\n", m);

		// SECTION HEADER total size
		blob += SECTION_HDR_SIZE;

		// MICROCODE HEADER
		printf("Microcode header:\n");

		struct microcode_header_amd *mha = (struct microcode_header_amd *)blob;

		printf("\t data code               = 0x%08x\n", mha->data_code);
		printf("\t patch id                = 0x%08x\n", mha->patch_id);
		printf("\t microcode patch data id = 0x%04x\n", mha->mc_patch_data_id);
// 		printf("\t nb dev id               = 0x%08x\n", mha->nb_dev_id);
// 		printf("\t sb dev id               = 0x%08x\n", mha->sb_dev_id);
		printf("\t processor rev id        = 0x%04x\n", mha->processor_rev_id);
// 		printf("\t nb revision id          = 0x%02x\n", mha->nb_rev_id);
// 		printf("\t sb revision id          = 0x%02x\n", mha->sb_rev_id);
// 		printf("\t BIOS API revision       = 0x%02x\n", mha->bios_api_rev);

		// MICROCODE HEADER total size
		blob += 64;

		// MICROCODE BLOB
		printf("Microcode blob:\n");

		printf("\t skipping %zu bytes\n", (size_t)(m-64));
		blob += m - 64;

		printf("\t (blob: position = %zu, total size = %zu)\n", (size_t)(blob - start), size);
	}

	return (size_t)(blob - start);
}

int main(int argc, char *argv[])
{
	const char *path = argc>1 ? argv[1] : "/lib/firmware/amd-ucode/microcode_amd_fam17h.bin";

	printf("loading '%s'...\n", path);

	size_t size;
	const char *blob = load_blob(path, &size);

	printf("loaded blob of %zu bytes\n", size);

	parse_blob(blob, size);

	free((void *)blob);
}
