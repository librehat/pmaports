// SPDX-License-Identifier: MIT
/*
 * Userspace HCI initialization and line-discipline attach daemon for
 * Unisoc UWE5622 / Marlin3-Lite Bluetooth over /dev/ttyBT0 (sprdbt_tty).
 *
 * Parses bt_configure_pskey.ini (160 B) and bt_configure_rf.ini (252 B),
 * clears the legacy LMP park bit for mainline BlueZ compatibility, sets a
 * deterministic BD_ADDR, sends VSCs 0xFCA0 / 0xFCA2 / 0xFCA1, attaches
 * N_HCI + H4, and stays resident until terminated.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#ifndef N_HCI
#define N_HCI 15
#endif

#ifndef HCIUARTSETPROTO
#define HCIUARTSETPROTO _IOW('U', 200, int)
#endif

#define HCI_UART_H4 0
#define PSKEY_SIZE 160
#define RF_SIZE 252

static volatile sig_atomic_t stop_requested;

static void handle_signal(int sig)
{
	(void)sig;
	stop_requested = 1;
}

struct ini_field {
	const char *name;
	uint16_t offset;
	uint8_t elem_size;
	uint8_t count;
};

static const struct ini_field pskey_fields[] = {
	/* [1.COMMON] 44 B */
	{ "device_class",                        0,   4, 1 },
	{ "feature_set",                         4,   1, 16 },
	{ "device_addr",                        20,   1, 6 },
	{ "comp_id",                            26,   2, 1 },
	{ "g_sys_uart0_communication_supported", 28,  1, 1 },
	{ "cp2_log_mode",                       29,   1, 1 },
	{ "LogLevel",                           30,   1, 1 },
	{ "g_central_or_perpheral",             31,   1, 1 },
	{ "Log_BitMask",                        32,   2, 1 },
	{ "super_ssp_enable",                   34,   1, 1 },
	{ "common_rfu_b3",                      35,   1, 1 },
	{ "common_rfu_w",                       36,   4, 2 },
	/* [2.LE] 8 B */
	{ "le_rfu_w",                           44,   4, 2 },
	/* [3.LMP] 8 B */
	{ "lmp_rfu_w",                          52,   4, 2 },
	/* [4.LC] 8 B */
	{ "lc_rfu_w",                           60,   4, 2 },
	/* [5.AUDIO] 20 B */
	{ "g_wbs_nv_117",                       68,   2, 1 },
	{ "g_wbs_nv_118",                       70,   2, 1 },
	{ "g_nbv_nv_117",                       72,   2, 1 },
	{ "g_nbv_nv_118",                       74,   2, 1 },
	{ "g_sys_sco_transmit_mode",            76,   1, 1 },
	{ "audio_rfu_b1",                       77,   1, 1 },
	{ "audio_rfu_b2",                       78,   1, 1 },
	{ "audio_rfu_b3",                       79,   1, 1 },
	{ "audio_rfu_w",                        80,   4, 2 },
	/* [6.POWER] 12 B */
	{ "g_sys_sleep_in_standby_supported",   88,   1, 1 },
	{ "g_sys_sleep_master_supported",       89,   1, 1 },
	{ "g_sys_sleep_slave_supported",        90,   1, 1 },
	{ "power_rfu_b1",                       91,   1, 1 },
	{ "power_rfu_w",                        92,   4, 2 },
	/* [7.BB] 16 B */
	{ "win_ext",                           100,   4, 1 },
	{ "edr_tx_edr_delay",                  104,   1, 1 },
	{ "edr_rx_edr_delay",                  105,   1, 1 },
	{ "tx_delay",                          106,   1, 1 },
	{ "rx_delay",                          107,   1, 1 },
	{ "bb_rfu_w",                          108,   4, 2 },
	/* [8.MODEM] 12 B */
	{ "agc_mode",                          116,   1, 1 },
	{ "diff_or_eq",                        117,   1, 1 },
	{ "ramp_mode",                         118,   1, 1 },
	{ "modem_rfu_b1",                      119,   1, 1 },
	{ "modem_rfu_w",                       120,   4, 2 },
	/* [9.OTHER] 32 B */
	{ "BQB_BitMask_1",                     128,   4, 1 },
	{ "BQB_BitMask_2",                     132,   4, 1 },
	{ "bt_coex_threshold",                 136,   2, 8 },
	{ "other_rfu_w",                       152,   4, 2 },
};

static const struct ini_field rf_fields[] = {
	/* [1.BT_RF_A] 112 B */
	{ "g_GainValue_A",                       0,   2, 6 },
	{ "g_ClassicPowerValue_A",              12,   2, 10 },
	{ "g_LEPowerValue_A",                   32,   2, 16 },
	{ "g_BRChannelpwrvalue_A",              64,   2, 8 },
	{ "g_EDRChannelpwrvalue_A",             80,   2, 8 },
	{ "g_LEChannelpwrvalue_A",              96,   2, 8 },
	/* [2.BT_RF_B] 112 B */
	{ "g_GainValue_B",                     112,   2, 6 },
	{ "g_ClassicPowerValue_B",             124,   2, 10 },
	{ "g_LEPowerValue_B",                  144,   2, 16 },
	{ "g_BRChannelpwrvalue_B",             176,   2, 8 },
	{ "g_EDRChannelpwrvalue_B",            192,   2, 8 },
	{ "g_LEChannelpwrvalue_B",             208,   2, 8 },
	/* [3.BT_RF_COMMON] 28 B */
	{ "LE_fix_powerword",                  224,   2, 1 },
	{ "Classic_pc_by_channel",             226,   1, 1 },
	{ "LE_pc_by_channel",                  227,   1, 1 },
	{ "RF_switch_mode",                    228,   1, 1 },
	{ "Data_Capture_Mode",                 229,   1, 1 },
	{ "Analog_IQ_Debug_Mode",              230,   1, 1 },
	{ "RF_common_rfu_b3",                  231,   1, 1 },
	{ "RF_common_rfu_w",                   232,   4, 5 },
};

static char *trim_whitespace(char *s)
{
	char *end;

	while (*s && isspace((unsigned char)*s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((unsigned char)end[-1]))
		*--end = '\0';
	return s;
}

static void put_le(uint8_t *dst, uint8_t size, unsigned long long val)
{
	for (uint8_t i = 0; i < size; i++)
		dst[i] = (uint8_t)((val >> (8 * i)) & 0xff);
}

static int parse_ini_blob(const char *path,
			  const struct ini_field *fields,
			  size_t num_fields,
			  uint8_t *out,
			  size_t out_size,
			  size_t *matched_out)
{
	FILE *fp;
	bool seen[64];
	char line[1024];
	size_t matched = 0;

	if (num_fields > sizeof(seen))
		return -EINVAL;

	memset(seen, 0, sizeof(seen));
	memset(out, 0, out_size);

	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "sprd-bt-attach: failed to open %s: %s\n",
			path, strerror(errno));
		return -errno;
	}

	while (fgets(line, sizeof(line), fp)) {
		char *comment = strchr(line, '#');
		char *eq;
		char *key;
		char *val_str;
		int idx = -1;

		if (comment)
			*comment = '\0';
		eq = strchr(line, '=');
		if (!eq)
			continue;

		*eq = '\0';
		key = trim_whitespace(line);
		val_str = trim_whitespace(eq + 1);
		if (!*key || !*val_str)
			continue;

		for (size_t i = 0; i < num_fields; i++) {
			if (strcmp(key, fields[i].name) == 0) {
				idx = (int)i;
				break;
			}
		}
		if (idx < 0)
			continue;

		const struct ini_field *f = &fields[idx];
		uint8_t parsed = 0;
		char *saveptr = NULL;
		char *tok = strtok_r(val_str, ",", &saveptr);

		while (tok && parsed < f->count) {
			char *t = trim_whitespace(tok);
			char *endptr = NULL;
			unsigned long long v;

			if (!*t) {
				tok = strtok_r(NULL, ",", &saveptr);
				continue;
			}
			errno = 0;
			v = strtoull(t, &endptr, 0);
			if (errno != 0 || endptr == t) {
				fprintf(stderr,
					"sprd-bt-attach: invalid value '%s' for %s in %s\n",
					t, key, path);
				fclose(fp);
				return -EINVAL;
			}
			size_t pos = (size_t)f->offset + (size_t)parsed * f->elem_size;
			if (pos + f->elem_size > out_size) {
				fclose(fp);
				return -EOVERFLOW;
			}
			put_le(out + pos, f->elem_size, v);
			parsed++;
			tok = strtok_r(NULL, ",", &saveptr);
		}

		if (parsed != f->count) {
			fprintf(stderr,
				"sprd-bt-attach: %s expected %u values, got %u in %s\n",
				f->name, f->count, parsed, path);
			fclose(fp);
			return -EINVAL;
		}
		if (!seen[idx]) {
			seen[idx] = true;
			matched++;
		}
	}

	fclose(fp);

	if (matched != num_fields) {
		for (size_t i = 0; i < num_fields; i++) {
			if (!seen[i])
				fprintf(stderr,
					"sprd-bt-attach: missing field %s in %s\n",
					fields[i].name, path);
		}
		return -EINVAL;
	}

	if (matched_out)
		*matched_out = matched;
	return 0;
}

static void derive_bdaddr(uint8_t mac[6])
{
	uint64_t h = 0xcbf29ce484222325ULL;
	int fd = open("/etc/machine-id", O_RDONLY);
	char buf[64];
	ssize_t n = 0;

	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf));
		close(fd);
	}
	if (n > 0) {
		for (ssize_t i = 0; i < n; i++) {
			h ^= (uint8_t)buf[i];
			h *= 0x100000001b3ULL;
		}
		for (int i = 0; i < 6; i++)
			mac[i] = (uint8_t)((h >> (8 * i)) & 0xff);
	} else {
		fd = open("/dev/urandom", O_RDONLY);
		if (fd >= 0) {
			if (read(fd, mac, 6) != 6) {
				mac[0] = 0x22;
				mac[1] = 0x56;
				mac[2] = 0x35;
				mac[3] = 0xa8;
				mac[4] = 0x00;
				mac[5] = 0x02;
			}
			close(fd);
		}
	}

	/* Locally administered, unicast (LSB byte order in BT PSKey). */
	mac[5] = (uint8_t)((mac[5] & 0xfe) | 0x02);
}

static void patch_pskey(uint8_t pskey[PSKEY_SIZE])
{
	static const uint8_t placeholder[6] = { 0x6d, 0x6d, 0x8e, 0x8e, 0x8f, 0x8f };
	static const uint8_t zeroes[6] = { 0 };

	/* Clear LMP park capability bit so mainline Write_Default_Link_Policy succeeds. */
	pskey[5] &= (uint8_t)~0x01;

	if (memcmp(pskey + 20, placeholder, 6) == 0 ||
	    memcmp(pskey + 20, zeroes, 6) == 0) {
		derive_bdaddr(pskey + 20);
	}
}

static void find_firmware_file(const char *rel, char *out, size_t out_sz)
{
	static const char * const prefixes[] = {
		"/usr/lib/firmware",
		"/lib/firmware",
	};

	for (size_t i = 0; i < 2; i++) {
		snprintf(out, out_sz, "%s/%s", prefixes[i], rel);
		if (access(out, R_OK) == 0)
			return;
	}
	snprintf(out, out_sz, "%s/%s", prefixes[0], rel);
}

static int unblock_bt_rfkill(void)
{
	DIR *dir = opendir("/sys/class/rfkill");
	struct dirent *ent;
	bool unblocked = false;

	if (!dir)
		return -errno;

	while ((ent = readdir(dir)) != NULL) {
		char type_path[300];
		char soft_path[300];
		char type_buf[32] = { 0 };
		char soft_buf[8] = { 0 };
		int fd;
		ssize_t n;

		if (strncmp(ent->d_name, "rfkill", 6) != 0)
			continue;

		snprintf(type_path, sizeof(type_path),
			 "/sys/class/rfkill/%s/type", ent->d_name);
		fd = open(type_path, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, type_buf, sizeof(type_buf) - 1);
		close(fd);
		if (n <= 0 || strncmp(type_buf, "bluetooth", 9) != 0)
			continue;

		snprintf(soft_path, sizeof(soft_path),
			 "/sys/class/rfkill/%s/soft", ent->d_name);
		fd = open(soft_path, O_RDWR);
		if (fd < 0)
			continue;
		n = read(fd, soft_buf, sizeof(soft_buf) - 1);
		if (n > 0 && soft_buf[0] == '1') {
			if (write(fd, "0\n", 2) == 2) {
				unblocked = true;
				fprintf(stderr,
					"sprd-bt-attach: unblocked %s\n",
					soft_path);
			}
		}
		close(fd);
	}

	closedir(dir);
	if (unblocked) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 300000000L };
		nanosleep(&ts, NULL);
	}
	return 0;
}

static int wait_for_tty(const char *dev, int timeout_sec)
{
	for (int i = 0; i < timeout_sec * 10; i++) {
		if (access(dev, R_OK | W_OK) == 0)
			return 0;
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000000L };
		nanosleep(&ts, NULL);
	}
	return -ENOENT;
}

static int write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t off = 0;

	while (off < len) {
		ssize_t n = write(fd, buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		off += (size_t)n;
	}
	return 0;
}

static int read_exact_timeout(int fd, uint8_t *buf, size_t len, int timeout_ms)
{
	size_t off = 0;

	while (off < len) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		int r = poll(&pfd, 1, timeout_ms);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (r == 0)
			return -ETIMEDOUT;
		if (!(pfd.revents & POLLIN))
			return -EIO;

		ssize_t n = read(fd, buf + off, len - off);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO;
		off += (size_t)n;
	}
	return 0;
}

static int send_vsc(int fd, uint16_t opcode, const uint8_t *payload, uint8_t plen)
{
	uint8_t cmd[4 + 255];

	cmd[0] = 0x01;
	cmd[1] = (uint8_t)(opcode & 0xff);
	cmd[2] = (uint8_t)((opcode >> 8) & 0xff);
	cmd[3] = plen;
	if (plen > 0)
		memcpy(cmd + 4, payload, plen);

	int ret = write_all(fd, cmd, 4 + (size_t)plen);
	if (ret < 0) {
		fprintf(stderr,
			"sprd-bt-attach: write VSC 0x%04X failed: %s\n",
			opcode, strerror(-ret));
		return ret;
	}

	for (int attempt = 0; attempt < 16; attempt++) {
		uint8_t hdr[3];
		uint8_t evbuf[260];

		ret = read_exact_timeout(fd, hdr, 1, 5000);
		if (ret < 0) {
			fprintf(stderr,
				"sprd-bt-attach: VSC 0x%04X timeout/err waiting packet type: %s\n",
				opcode, strerror(-ret));
			return ret;
		}
		if (hdr[0] != 0x04) {
			fprintf(stderr,
				"sprd-bt-attach: unexpected H4 packet type 0x%02x waiting 0x%04X\n",
				hdr[0], opcode);
			return -EPROTO;
		}
		ret = read_exact_timeout(fd, hdr + 1, 2, 5000);
		if (ret < 0)
			return ret;

		uint8_t evt = hdr[1];
		uint8_t evlen = hdr[2];
		if (evlen > 0) {
			ret = read_exact_timeout(fd, evbuf, evlen, 5000);
			if (ret < 0)
				return ret;
		}

		if (evt == 0x0e && evlen >= 4) {
			uint16_t rx_op = (uint16_t)evbuf[1] | ((uint16_t)evbuf[2] << 8);
			uint8_t status = evbuf[3];
			if (rx_op == opcode) {
				fprintf(stderr,
					"sprd-bt-attach: VSC 0x%04X -> status=0x%02x\n",
					opcode, status);
				return status == 0 ? 0 : -EIO;
			}
		} else if (evt == 0x0f && evlen >= 4) {
			uint16_t rx_op = (uint16_t)evbuf[2] | ((uint16_t)evbuf[3] << 8);
			uint8_t status = evbuf[0];
			if (rx_op == opcode && status != 0) {
				fprintf(stderr,
					"sprd-bt-attach: VSC 0x%04X Command Status=0x%02x\n",
					opcode, status);
				return -EIO;
			}
		}
	}

	fprintf(stderr, "sprd-bt-attach: VSC 0x%04X did not receive Command Complete\n",
		opcode);
	return -ETIMEDOUT;
}

static int run_dry_run(const char *pskey_path, const char *rf_path)
{
	uint8_t pskey[PSKEY_SIZE];
	uint8_t rf[RF_SIZE];
	size_t pskey_count = 0;
	size_t rf_count = 0;

	if (parse_ini_blob(pskey_path, pskey_fields,
			   sizeof(pskey_fields) / sizeof(pskey_fields[0]),
			   pskey, sizeof(pskey), &pskey_count) < 0)
		return 1;
	patch_pskey(pskey);

	if (parse_ini_blob(rf_path, rf_fields,
			   sizeof(rf_fields) / sizeof(rf_fields[0]),
			   rf, sizeof(rf), &rf_count) < 0)
		return 1;

	printf("dry-run OK: pskey=%zu/%zu fields (%zu B), feature_set[1]=0x%02x, bdaddr=%02x:%02x:%02x:%02x:%02x:%02x; rf=%zu/%zu fields (%zu B)\n",
	       pskey_count, sizeof(pskey_fields) / sizeof(pskey_fields[0]),
	       sizeof(pskey), pskey[5],
	       pskey[25], pskey[24], pskey[23], pskey[22], pskey[21], pskey[20],
	       rf_count, sizeof(rf_fields) / sizeof(rf_fields[0]),
	       sizeof(rf));
	return 0;
}

int main(int argc, char **argv)
{
	const char *tty_dev = "/dev/ttyBT0";
	char pskey_path[256];
	char rf_path[256];
	uint8_t pskey[PSKEY_SIZE];
	uint8_t rf[RF_SIZE];
	static const uint8_t enable_dual[3] = { 0x00, 0x00, 0x01 };
	struct termios tio;
	int fd;
	int ldisc = N_HCI;
	int proto = HCI_UART_H4;

	if (argc >= 2 && strcmp(argv[1], "--dry-run") == 0) {
		if (argc != 4) {
			fprintf(stderr, "Usage: %s --dry-run <pskey.ini> <rf.ini>\n",
				argv[0]);
			return 2;
		}
		return run_dry_run(argv[2], argv[3]);
	}

	if (argc >= 2)
		tty_dev = argv[1];

	find_firmware_file("uwe5622/bt_configure_pskey.ini",
			   pskey_path, sizeof(pskey_path));
	find_firmware_file("uwe5622/bt_configure_rf.ini",
			   rf_path, sizeof(rf_path));

	if (parse_ini_blob(pskey_path, pskey_fields,
			   sizeof(pskey_fields) / sizeof(pskey_fields[0]),
			   pskey, sizeof(pskey), NULL) < 0)
		return 1;
	patch_pskey(pskey);

	if (parse_ini_blob(rf_path, rf_fields,
			   sizeof(rf_fields) / sizeof(rf_fields[0]),
			   rf, sizeof(rf), NULL) < 0)
		return 1;

	if (wait_for_tty(tty_dev, 30) < 0) {
		fprintf(stderr, "sprd-bt-attach: timed out waiting for %s\n",
			tty_dev);
		return 1;
	}

	unblock_bt_rfkill();

	fd = open(tty_dev, O_RDWR | O_NOCTTY);
	if (fd < 0) {
		fprintf(stderr, "sprd-bt-attach: open %s failed: %s\n",
			tty_dev, strerror(errno));
		return 1;
	}

	if (tcgetattr(fd, &tio) == 0) {
		cfmakeraw(&tio);
		cfsetispeed(&tio, B115200);
		cfsetospeed(&tio, B115200);
		tio.c_cflag |= (CS8 | CREAD | CLOCAL);
		tio.c_cc[VMIN] = 1;
		tio.c_cc[VTIME] = 0;
		tcsetattr(fd, TCSANOW, &tio);
	}
	tcflush(fd, TCIOFLUSH);

	if (send_vsc(fd, 0xFCA0, pskey, sizeof(pskey)) < 0 ||
	    send_vsc(fd, 0xFCA2, rf, sizeof(rf)) < 0 ||
	    send_vsc(fd, 0xFCA1, enable_dual, sizeof(enable_dual)) < 0) {
		close(fd);
		return 1;
	}

	if (ioctl(fd, TIOCSETD, &ldisc) < 0) {
		fprintf(stderr, "sprd-bt-attach: TIOCSETD(N_HCI) failed: %s\n",
			strerror(errno));
		close(fd);
		return 1;
	}

	if (ioctl(fd, HCIUARTSETPROTO, proto) < 0) {
		fprintf(stderr, "sprd-bt-attach: HCIUARTSETPROTO(H4) failed: %s\n",
			strerror(errno));
		close(fd);
		return 1;
	}

	fprintf(stderr, "sprd-bt-attach: attached HCI H4 on %s\n", tty_dev);

	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);
	while (!stop_requested)
		pause();

	close(fd);
	return 0;
}
