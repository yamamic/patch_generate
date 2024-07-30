/*
 * Driver interaction with extended Linux CFG8021
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 */
#include "includes.h"
#include "netlink/genl/genl.h"
#include <sys/ioctl.h>

#include "common.h"
#include "driver_nl80211.h"
#include "linux_ioctl.h"
#include "../../wpa_supplicant/wpa_supplicant_i.h"
#include "config.h"
#include "android_drv.h"

#include "mediatek_driver_nl80211.h"
#include "../../wpa_supplicant/driver_i.h"


#include "eloop.h"

/**********************************************************************
* OVERLAPPED functins, previous defination is in driver_nl80211.c,
* it will be modified
***********************************************************************/

/**********************************************************************/

static int mtk_set_mlo_preset_link_id(void *priv, const char *cmd)
{
    struct i802_bss *bss = priv;
    struct wpa_driver_nl80211_data *drv = bss->drv;
    struct nl_msg *msg;
    struct nlattr *params;
    int ret;
	int link_id = 0;

    wpa_printf(MSG_DEBUG, "mtk string command: %s", cmd);

	if (os_strncasecmp(cmd, "PRESET_LINKID=", os_strlen("PRESET_LINKID=")) != 0) {
		wpa_printf(MSG_ERROR, "command: %s, not supported.", cmd);
		return -1;
	}
	ret = sscanf(cmd, "PRESET_LINKID=%d", &link_id);
	if (ret != 1 || link_id >= ML_MAX_LINK_NUM) {
		wpa_printf(MSG_ERROR, "command: %s, invalid format or value.", cmd);
		return -1;
	}
	wpa_printf(MSG_DEBUG, "mtk string command: %s, link_id=%d", cmd, link_id);
    if (!(msg = nl80211_drv_msg(drv, 0, NL80211_CMD_VENDOR)) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_ID, OUI_MTK) ||
        nla_put_u32(msg, NL80211_ATTR_VENDOR_SUBCMD,
                    MTK_NL80211_VENDOR_SUBCMD_SET_MLO_PRESET_LINK)) {
        wpa_printf(MSG_ERROR, "nl operation error");
        goto fail;
    }

    params = nla_nest_start(msg, NL80211_ATTR_VENDOR_DATA);
    if (!params) {
        wpa_printf(MSG_ERROR, "nl start failed");
        goto fail;
    }

	if (nla_put_u8(msg, MTK_NL80211_VENDOR_ATTR_MLO_PRESET_LINKID_INFO, (u8)link_id)) {
        wpa_printf(MSG_ERROR, "nl put attribute failed");
        goto fail;
    }

    nla_nest_end(msg, params);

    ret = send_and_recv_msgs(drv, msg, NULL, NULL, NULL, NULL);
    msg = NULL;
    if (ret) {
        wpa_printf(MSG_ERROR, "str_vendor_cmd ret=%d", ret);
        return ret;
    }
    return 0;
fail:
    nlmsg_free(msg);
    return -1;
}


int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf,
                  size_t buf_len)
{
    struct i802_bss *bss = priv;
    struct wpa_driver_nl80211_data *drv = bss->drv;
    struct ifreq ifr;
    struct wpa_supplicant *wpa_s = NULL;
    struct hostapd_data *hapd;
    int handled = 0;
    int cmd_len = 0;
    union wpa_event_data event;
    static int user_force_band = 0;
    int ret = -1;

    if (drv == NULL) {
        wpa_printf(MSG_ERROR, "%s: drv is NULL, exit", __func__);
        return -1;
    }
    if (drv->ctx == NULL) {
        wpa_printf(MSG_ERROR, "%s: drv->ctx is NULL, exit", __func__);
        return -1;
    }

    if (bss->drv->nlmode == NL80211_IFTYPE_AP) {
        hapd = (struct hostapd_data *)(drv->ctx);
    }
    else {
        wpa_s = (struct wpa_supplicant *)(drv->ctx);
        if (wpa_s->conf == NULL) {
            wpa_printf(MSG_ERROR, "%s: wpa_s->conf is NULL, exit", __func__);
            return -1;
        }
    }

    wpa_printf(MSG_INFO, "%s: %s recv cmd %s", __func__, bss->ifname, cmd);
    handled = 0;

    if (os_strncasecmp(cmd, "PRESET_LINKID=", os_strlen("PRESET_LINKID=")) == 0) {
        wpa_printf(MSG_DEBUG, "%s", cmd);
		if (mtk_set_mlo_preset_link_id(priv, cmd) != 0) {
			wpa_printf(MSG_ERROR, "%s: mtk_set_mlo_preset_link_id fail.", __func__);
            return -1;
		}
	}else {
		wpa_printf(MSG_ERROR, "%s command not supported.", cmd);
	}
    return ret;
}



void mtk_nl80211_mlo_response_event(struct wpa_driver_nl80211_data *drv,
                u8 *data, size_t data_len)
{
    const u8 *end, *pos;

    wpa_hexdump(MSG_INFO, "nl80211: mtk generic_response_event", data, data_len);

    pos = data;
    end = data + data_len;
    while (end - pos >= 2) {
        u8 id, len;

        id = *pos++;
        len = *pos++;
        if (len > end - pos)
            break;

        switch (id) {
        /* add cases for different event id here */
        case MTK_GRID_MLO_EXTERNAL_AUTH:
        {
             struct mtk_externa_auth_info *info =
                 (struct mtk_externa_auth_info *) pos;
             union wpa_event_data event;
             enum nl80211_external_auth_action act;

             os_memset(&event, 0, sizeof(event));
             act = info->action;
             switch (act) {
             case NL80211_EXTERNAL_AUTH_START:
                     event.external_auth.action = EXT_AUTH_START;
                     break;
             case NL80211_EXTERNAL_AUTH_ABORT:
                     event.external_auth.action = EXT_AUTH_ABORT;
                     break;
             default:
                     return;
             }

             event.external_auth.key_mgmt_suite = info->key_mgmt_suite;
             event.external_auth.ssid_len = info->ssid_len;
             if (event.external_auth.ssid_len > SSID_MAX_LEN)
                     return;
             event.external_auth.ssid = info->ssid;
             event.external_auth.bssid = info->bssid;
#ifdef CONFIG_MTK_IEEE80211BE
             event.external_auth.ext_ie = info->ext_ie;
             event.external_auth.ext_ie_len = len - sizeof(*info);
#endif /* CONFIG_MTK_IEEE80211BE */
             wpa_printf(MSG_DEBUG,
                        "nl80211: mtk external auth action: %u, AKM: 0x%x, bssid["MACSTR"], da["MACSTR"]",
                        event.external_auth.action,
                        event.external_auth.key_mgmt_suite,
                        MAC2STR(info->bssid),
                        MAC2STR(info->da));
             wpa_supplicant_event(drv->ctx, EVENT_EXTERNAL_AUTH, &event);
        }
             break;
        default:
            wpa_printf(MSG_DEBUG, "unknown generic response: %u", id);
            break;
        }
        pos += len;
    }
}

static void mtk_ml80211_bss_ml_info_event(struct wpa_driver_nl80211_data *drv, struct i802_bss *bss,
					u8 *data, size_t len)
{
	union wpa_event_data *event = nla_data((struct nlattr *)data);

	if (event)
		wpa_supplicant_event(bss->ctx, EVENT_UPDATE_BSS_ML_INFO, event);
}

void mtk_nl80211_mlo_sta_profile_event(struct wpa_driver_nl80211_data *drv,
                u8 *data, size_t data_len)
{
	const u8 *end, *pos;
	u16 sta_ctrl;
	u8 i = 0;
	struct per_sta_profile profile[ML_MAX_LINK_NUM];
	union wpa_event_data event;

    wpa_hexdump(MSG_INFO, "nl80211: mtk_nl80211_mlo_sta_profile_event", data, data_len);
	wpa_hexdump(MSG_MSGDUMP, "Per-STA Profile sub-IE", data, data_len);

	pos = data;
    end = data + data_len;

	/* skip event header */
	pos += 4;

	/* pos point to link info, recusive parse it */
	while (pos < end) {
		u8 sta_info_len;
		const u8 *head, *tail;

		if (*pos != ML_SUB_ID_PER_STA_PROFILE)
			break;

		head = pos + 2;
		tail = head + pos[1];
		pos += 2;
		sta_ctrl = WPA_GET_LE16(pos);
		pos += 2;

		profile[i].link_id = sta_ctrl & ML_STA_CTRL_LINK_ID_MASK;
		profile[i].complete_profile =
			(sta_ctrl & ML_STA_CTRL_COMPLETE_PROFILE) > 0;

		wpa_printf(MSG_INFO, "ML: LinkID=%u Ctrl=0x%x(%s)",
			profile[i].link_id, sta_ctrl,
			profile[i].complete_profile ? "COMPLETE" : "PARTIAL");

		sta_info_len = *pos++;

		if (sta_ctrl & ML_STA_CTRL_MAC_ADDR_PRESENT) {
			os_memcpy(profile[i].addr, pos, ETH_ALEN);
			profile[i].mac_addr_present = 1;
			wpa_printf(MSG_INFO, "ML: LinkID=%u, LinkAddr="MACSTR"",
				profile[i].link_id, MAC2STR(profile[i].addr));
			pos += ETH_ALEN;
		}
		if (sta_ctrl & ML_STA_CTRL_BCN_INTV_PRESENT) {
			profile[i].beacon_interval = WPA_GET_LE16(pos);
			profile[i].bcn_intvl_present = 1;
			wpa_printf(MSG_INFO, "ML: LinkID=%u, BCN_INTV = %u",
				profile[i].link_id, profile[i].beacon_interval);
			pos += 2;
		}
		if (sta_ctrl & ML_STA_CTRL_DTIM_INFO_PRESENT) {
			profile[i].dtim = WPA_GET_LE16(pos);
			profile[i].dtim_present = 1;
			wpa_printf(MSG_INFO, "ML: LinkID=%u, DTIM_INFO = 0x%x",
				profile[i].link_id, profile[i].dtim);
			pos += 2;
		}
		/* If the Complete Profile subfield = 1 and
		 * NSTR Link Pair Present = 1, then NSTR Indication Bitmap exist
		 * NSTR Bitmap Size = 1 if the length of the corresponding
		 * NSTR Indication Bitmap is 2 bytes, and = 0 if the
		 * length of the corresponding NSTR Indication Bitmap = 1 byte
		 */
		if ((sta_ctrl & ML_STA_CTRL_COMPLETE_PROFILE) &&
			(sta_ctrl & ML_STA_CTRL_NSTR_LINK_PAIR_PRESENT)) {
			if (((sta_ctrl & ML_STA_CTRL_NSTR_BMP_SIZE) >>
				ML_STA_CTRL_NSTR_BMP_SIZE_SHIFT) == 0) {
				profile[i].nstr_bmap = *pos;
				wpa_printf(MSG_INFO, "ML: LinkID=%u, NSTR_BMP0=0x%x",
					profile[i].link_id, profile[i].nstr_bmap);
				pos += 1;
			} else {
				profile[i].nstr_bmap = WPA_GET_LE16(pos);
				wpa_printf(MSG_INFO, "ML: LinkID=%u, NSTR_BMP1=0x%x",
					profile[i].link_id, profile[i].nstr_bmap);
				pos += 2;
			}
			profile[i].nstr_present = 1;
		}
		if (pos - (head + 2) != sta_info_len) {
			wpa_printf(MSG_INFO, "ML: invalid ML STA info len = %u",
				sta_info_len);
		}

		os_memcpy(&event.profiles[i], &profile[i], sizeof(struct per_sta_profile));

		/* point to next Per-STA profile*/
		pos = tail;
		i++;
	}

	wpa_supplicant_event(drv->ctx, EVENT_UPDATE_STA_PROFILE_UPDATE, &event);
}

static enum hostapd_hw_mode get_mtk_hw_mode(u8 hw_mode)
{
	switch (hw_mode) {
	case MTK_ACS_MODE_IEEE80211B:
		return HOSTAPD_MODE_IEEE80211B;
	case MTK_ACS_MODE_IEEE80211G:
		return HOSTAPD_MODE_IEEE80211G;
	case MTK_ACS_MODE_IEEE80211A:
		return HOSTAPD_MODE_IEEE80211A;
	case MTK_ACS_MODE_IEEE80211AD:
		return HOSTAPD_MODE_IEEE80211AD;
	case MTK_ACS_MODE_IEEE80211ANY:
		return HOSTAPD_MODE_IEEE80211ANY;
	default:
		return NUM_HOSTAPD_MODES;
	}
}


void mtk_nl80211_acs_complete_event(struct wpa_driver_nl80211_data *drv,
                u8 *data, size_t data_len)
{
    struct nlattr *tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_EVENT_MAX + 1];
	union wpa_event_data event;
	u8 chan;

	wpa_printf(MSG_DEBUG,
		   "nl80211: ACS channel selection vendor event received");



	if (nla_parse(tb, MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_EVENT_MAX,
		      (struct nlattr *) data, data_len, NULL) ||
	    (!tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_PRIMARY_FREQUENCY]) ||
	    (!tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_SECONDARY_FREQUENCY]))
		return;


	os_memset(&event, 0, sizeof(event));
	event.acs_selected_channels.hw_mode = NUM_HOSTAPD_MODES;

	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_HW_MODE]) {
		u8 hw_mode = nla_get_u8(tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_HW_MODE]);

		event.acs_selected_channels.hw_mode = get_mtk_hw_mode(hw_mode);
		if (event.acs_selected_channels.hw_mode == NUM_HOSTAPD_MODES ||
		    event.acs_selected_channels.hw_mode ==
		    HOSTAPD_MODE_IEEE80211ANY) {
			wpa_printf(MSG_DEBUG,
				   "nl80211: Invalid hw_mode %u in ACS selection event",
				   hw_mode);
			return;
		}
	}

	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_PRIMARY_FREQUENCY]) {
		event.acs_selected_channels.pri_freq = nla_get_u32(
			tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_PRIMARY_FREQUENCY]);
	}

	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_SECONDARY_FREQUENCY]) {
		event.acs_selected_channels.sec_freq = nla_get_u32(
			tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_SECONDARY_FREQUENCY]);
	}

	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_EDMG_CHANNEL])
		event.acs_selected_channels.edmg_channel =
			nla_get_u8(tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_EDMG_CHANNEL]);
	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_VHT_SEG0_CENTER_CHANNEL])
		event.acs_selected_channels.vht_seg0_center_ch =
			nla_get_u8(tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_VHT_SEG0_CENTER_CHANNEL]);
	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_VHT_SEG1_CENTER_CHANNEL])
		event.acs_selected_channels.vht_seg1_center_ch =
			nla_get_u8(tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_VHT_SEG1_CENTER_CHANNEL]);
	if (tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_CHWIDTH])
		event.acs_selected_channels.ch_width =
			nla_get_u16(tb[MTK_NL80211_VENDOR_ATTR_EVENT_ACS_COMPLETE_CHWIDTH]);
	wpa_printf(MSG_INFO,
		   "nl80211: ACS Results: PFreq: %u SFreq: %u BW: %u VHT0: %u VHT1: %u HW_MODE: %d EDMGCH: %u",
		   event.acs_selected_channels.pri_freq,
		   event.acs_selected_channels.sec_freq,
		   event.acs_selected_channels.ch_width,
		   event.acs_selected_channels.vht_seg0_center_ch,
		   event.acs_selected_channels.vht_seg1_center_ch,
		   event.acs_selected_channels.hw_mode,
		   event.acs_selected_channels.edmg_channel);

	/* Ignore ACS channel list check for backwards compatibility */

	wpa_supplicant_event(drv->ctx, EVENT_ACS_CHANNEL_SELECTED, &event);
}

void mtk_nl80211_rxt2lm_stop_disassoc_timer_event(struct wpa_driver_nl80211_data *drv,
		u8 *data, size_t data_len)
{
	struct hostapd_data *hapd = drv->ctx;
	struct sta_info *sta, *prev;
	struct hostapd_iface *h_iface = NULL;
	struct hostapd_data *h_hapd = NULL;
	int i = 0;

	for (i = 0; i < hapd->iface->interfaces->count; i++) {
		h_iface = hapd->iface->interfaces->iface[i];
		if (h_iface)
			h_hapd = h_iface->bss[0];

		if(h_hapd) {
			sta = h_hapd->sta_list;
			while (sta) {
				prev = sta;
				if (sta->flags & WLAN_STA_ASSOC) {
					wpa_printf(MSG_DEBUG,"cancelling timer for STA" MACSTR, MAC2STR(sta->addr));
					eloop_cancel_timeout(ap_handle_timer, h_hapd, sta);
				}
				sta = sta->next;
			}
		}
	}
}

void mtk_nl80211_rx_sta_link_mac_event(struct wpa_driver_nl80211_data *drv,
		u8 *data, size_t data_len)
{
	struct hostapd_data *hapd = drv->ctx;

	hapd->update_sta_link_mac = 1;
	os_memcpy(hapd->sta_link_addr, data + 4, ETH_ALEN);
	wpa_hexdump(MSG_MSGDUMP, "Sta Link Mac", data, data_len);
}

void nl80211_vendor_event_mtk(struct wpa_driver_nl80211_data *drv, struct i802_bss *bss,
                  u32 subcmd, u8 *data, size_t len)
{
    switch (subcmd) {
		case MTK_NL80211_VENDOR_EVENT_SEND_ML_INFO:
			mtk_ml80211_bss_ml_info_event(drv, bss, data, len);
			break;
	    case MTK_NL80211_VENDOR_EVENT_MLO_EVENT:
			wpa_printf(MSG_INFO,
	            "nl80211: MTK_NL80211_VENDOR_EVENT_MLO_EVENT event %u", subcmd);
	        mtk_nl80211_mlo_response_event(drv, data, len);
	        break;
		case MTK_NL80211_VENDOR_EVENT_STA_PROFILE_EVENT:
			wpa_printf(MSG_INFO,
	            "nl80211: MTK_NL80211_VENDOR_EVENT_STA_PROFILE_EVENT event %u", subcmd);
	        mtk_nl80211_mlo_sta_profile_event(drv, data, len);
	        break;
        case MTK_NL80211_VENDOR_EVENT_ACS_COMPLETE_EVENT:
			wpa_printf(MSG_INFO,
	            "nl80211: MTK_NL80211_VENDOR_EVENT_ACS_COMPLETE_EVENT event %u", subcmd);
            mtk_nl80211_acs_complete_event(drv, data, len);
            break;
	case MTK_NL80211_VENDOR_EVENT_RX_T2LM_STOP_DISASSOC_TIMER:
		wpa_printf(MSG_DEBUG,
		"nl80211: MTK_NL80211_VENDOR_EVENT_RX_T2LM_STOP_DISASSOC_TIMER event %u", subcmd);
		mtk_nl80211_rxt2lm_stop_disassoc_timer_event(drv, data, len);
		break;
	case MTK_NL80211_VENDOR_EVENT_SEND_MLO_STA_LINK_MAC:
		wpa_printf(MSG_DEBUG,
		"nl80211: MTK_NL80211_VENDOR_EVENT_SEND_MLO_STA_LINK_MAC event %u", subcmd);
		mtk_nl80211_rx_sta_link_mac_event(drv, data, len);
		break;
	    default:
	        wpa_printf(MSG_DEBUG,
	            "nl80211:Ignore unsupported mtk vendor event %u, MTK_NL80211_VENDOR_EVENT_MLO_EVENT(%u)",
	            subcmd, MTK_NL80211_VENDOR_EVENT_MLO_EVENT);
	        break;
    }
}



