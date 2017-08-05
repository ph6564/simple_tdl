/* packet-simple.c
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>

# include "simple.h"

typedef struct ST_ProtocoleSimplePrive
{
	int info;
	int proto_simple;/* Wireshark ID of the SIMPLE protocol */

}T_ProtocoleSimplePrive;

#include <string.h>

#define PROTO_TAG_SIMPLE	"SIMPLE"
/* Wireshark ID of the simple protocol */
static int proto_simple = -1;


/* These are the handles of our subdissectors */
static dissector_handle_t data_handle=NULL;

static dissector_handle_t simple_handle;
void dissect_simple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *prive);

static int global_simple_port = 999;

const value_string simple_packettypenames[] = {
	{ 0, "Illegal" },
	{ 1, "Link 16" },
	{ 2, "Link 11" },
	{ 3, "Link 4" },
	{ 32, "DIS Protocol Data Unit (PDU)" },
	{ 4, "Link 22 "},
	{ 63, "Round Trip Timing (RTT)" },
	{ 65, "Time Synchronisation" },
	{ 0, NULL }
};	


/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_simple()
*/



typedef struct ST_SimpleData
{
	gint encoding;
	struct 
	{
		struct 
		{
			gint id;
			gint header;
			gint length;
			gint sequence;
			gint data;
			gint checksum;

		}hf;
		struct 
		{
			gint id;
			gint header;
			gint length;
			gint sequence;
			gint data;
			gint checksum;
		}ett;
#define C_Longueur_network		7

		hf_register_info info[7];
	}network;
	struct 
	{
		struct 
		{
			gint id;
			gint source_node;
			gint source_subnode;
			gint destination_node;
			gint destination_subnode;
			gint size;
			gint type;
			gint transit_time;
			gint data;
		}hf;
		struct 
		{
			gint id;
			gint source_node;
			gint source_subnode;
			gint destination_node;
			gint destination_subnode;
			gint size;
			gint type;
			gint transit_time;
			gint data;
		}ett;
#define C_Longueur_packet		9
		hf_register_info info[C_Longueur_packet];
	}packet;
	struct 
	{
		struct 
		{
			gint id;
			gint subtype;
			gint rc_flag;
			gint net;
			gint slot_count_2;
			gint npg;
			gint slot_count_1;
			gint stn;
			gint word_count;
			gint loopback_id;
			gint data;
		}hf;
		struct 
		{
			gint id;
			gint subtype;
			gint rc_flag;
			gint net;
			gint slot_count_2;
			gint npg;
			gint slot_count_1;
			gint stn;
			gint word_count;
			gint loopback_id;
			gint data;
		}ett;
#define C_Longueur_link_16		11
		hf_register_info info[C_Longueur_link_16];
	}link_16;
	//
    //L11
	//
	struct 
	{
		struct 
		{
			gint id;
			gint subtype;
			gint pu;
			gint sequence_number;
			gint word_count;
			gint data;
		}hf;
		struct 
		{
			gint id;
			gint subtype;
			gint pu;
			gint sequence_number;
			gint word_count;
			gint data;
		}ett;
#define C_Longueur_link_11		6
		hf_register_info info[C_Longueur_link_11];
	}link_11;
	//
    //L11B
	//
	struct 
	{
		struct 
		{
			gint id;
			gint destination_pu;
			gint source_pu;
			gint word_count;
			gint data;
		}hf;
		struct 
		{
			gint id;
			gint destination_pu;
			gint source_pu;
			gint word_count;
			gint data;
		}ett;
#define C_Longueur_link_11b		5
		hf_register_info info[C_Longueur_link_11b];
	}link_11b;
	//
    //DIS
	//
	struct 
	{
		struct 
		{
			gint id;
			gint data;
		}hf;
		struct 
		{
			gint id;
			gint data;
		}ett;
#define C_Longueur_dis	2
		hf_register_info info[C_Longueur_dis];
	}dis;
	//
    //PACKET TYPE (61) - STATUS/CONFIGURATION -NODE STATUS MESSAGE - 1 -
	//
	struct 
	{
		struct 
		{
			gint id;
			gint subtype;
			gint number_of_words;
			gint name;
			gint node_id;
			gint hours;
			gint minutes;
			gint secondes;
			gint security_level;
			gint node_entry;
			gint relay_hope_node;
			gint DX;
			gint DX_file_id;
			gint mids_jtids_role;
			gint mids_jtids_terminal_type;
			gint mids_jtids_terminal_host_status;
			gint mids_jtids_synch_status;
			gint mids_jtids_stn;
			gint link11_dts_type;
			gint link11_role;
			gint link11_pu;
			gint link11_dts_host_status;
		}hf;
		struct 
		{
			gint id;
			gint subtype;
			gint number_of_words;
			gint name;
			gint node_id;
			gint hours;
			gint minutes;
			gint secondes;
			gint security_level;
			gint node_entry;
			gint relay_hope_node;
			gint DX;
			gint DX_file_id;
			gint mids_jtids_role;
			gint mids_jtids_terminal_type;
			gint mids_jtids_terminal_host_status;
			gint mids_jtids_synch_status;
			gint mids_jtids_stn;
			gint link11_dts_type;
			gint link11_role;
			gint link11_pu;
			gint link11_dts_host_status;
		}ett;
#define C_Longueur_node_status	23
		hf_register_info info[C_Longueur_node_status];
	}node_status;
	//
    //PACKET TYPE (63) - ROUND TRIP TIMING (RTT)
	//
#define C_Longueur_rtt	4
#define C_Longueur_time_synchro	4
	struct 
	{
		struct 
		{
			gint id;
			gint node;
			gint port;
			gint time_stamp;
		}hf;
		struct 
		{
			gint id;
			gint node;
			gint port;
			gint time_stamp;
		}ett;
		hf_register_info info[C_Longueur_rtt];
	}rtt;
	//
    //PACKET TYPE (65) - TIME SYNCHRONISATION
	//
	struct 
	{
		struct 
		{
			gint id;
			gint node;
			gint utc;
			gint exercise_offset;
		}hf;
		struct 
		{
			gint id;
			gint node;
			gint utc;
			gint exercise_offset;
		}ett;
		hf_register_info info[C_Longueur_time_synchro];
	}time_synchro;

	gint *ett[C_Longueur_packet   + C_Longueur_network + C_Longueur_link_16     + C_Longueur_link_11 + 
		      C_Longueur_link_11b + C_Longueur_dis     + C_Longueur_node_status + C_Longueur_rtt     + 
			  C_Longueur_time_synchro ];
	hf_register_info hf[C_Longueur_packet   + C_Longueur_network + C_Longueur_link_16     + C_Longueur_link_11 + 
		      C_Longueur_link_11b + C_Longueur_dis     + C_Longueur_node_status + C_Longueur_rtt     + 
			  C_Longueur_time_synchro ];

}T_SimpleData;

static T_SimpleData simple= {
	//encoding
	ENC_NA,
	//network 
	{
		{ -1, -1, -1, -1,  -1, -1},//network hf
		{ -1, -1, -1, -1,  -1, -1},//network ett
		{
			{ &simple.network.hf.header,
			{ "Packet", "simple.packet", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet", HFILL }},

			{ &simple.network.hf.header,
			{ "Header", "simple.header", FT_BYTES, BASE_HEX, NULL, 0x0,
			"SIMPLE Header", HFILL }},

			{ &simple.network.hf.length,
			{ "Package Length", "simple.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Package Length", HFILL }},

			{ &simple.network.hf.sequence,
			{ "Package Length", "simple.sequence", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Sequence Numbre by Node", HFILL }},	


			{ &simple.network.hf.data,
			{ "Data", "simple.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"data", HFILL }},

			{ &simple.network.hf.checksum,
			{ "Checksum", "simple.checksum", FT_UINT16, BASE_NONE, NULL, 0x0,
			"checksum", HFILL }}
		}//info
	},
	//packet 
	{
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1 },// hf
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1 },// ett
		{
			{ &simple.network.hf.id,
			{ "Packet", "simple.packet", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet", HFILL }},

			{ &simple.packet.hf.source_node,
			{ "Source Node", "simple.packet.source_node", FT_UINT8, BASE_DEC, VALS(SimpleLibelleNode), 0x0,
			"Source Node", HFILL }},

			{ &simple.packet.hf.source_subnode,
			{ "Source Subnode", "simple.packet.source_subnode", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSubNode), 0x0,
			"Source Subnode", HFILL }},

			{ &simple.packet.hf.destination_node,
			{ "Destination Node", "simple.packet.destination_node", FT_UINT8, BASE_DEC, VALS(SimpleLibelleNode), 0x0,
			"Destination Node", HFILL }},

			{ &simple.packet.hf.destination_subnode,
			{ "Destination Subnode", "simple.packet.destination_subnode", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSubNode), 0x0,
			"Destination Subnode", HFILL }},

			{ &simple.packet.hf.size,
			{ "Packet Size", "simple.packet.size", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Packet Size", HFILL }},

			{ &simple.packet.hf.type,
			{ "Type", "simple.packet.type", FT_UINT8, BASE_DEC, VALS(simple_packettypenames), 0x0,
			"Simple Packet Type", HFILL }}, 

			{ &simple.packet.hf.transit_time,
			{ "Transit Time", "simple.packet.transit_time", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Packet Transit Time", HFILL }},

			{ &simple.packet.hf.data,
			{ "Data", "simple.packet.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Simple Packet Data", HFILL }} 			
		}//info
	},
	//L16 
	{
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1, -1,  -1 },// hf
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1, -1,  -1 },// ett
		{
			{ &simple.packet.hf.id,
			{ "L16", "simple.L16", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet L16", HFILL }},

			{ &simple.link_16.hf.subtype,
			{ "Sub-Type", "simple.L16.subtype", FT_UINT8, BASE_DEC, VALS(SimpleLibelleL16SubType), 0x0,
			"Sub-Type", HFILL }},

			{ &simple.link_16.hf.rc_flag,
			{ "R/C Flag", "simple.L16.rc_flag", FT_UINT8, BASE_DEC, NULL, 0x0,
			"R/C Flag", HFILL }},

			{ &simple.link_16.hf.net,
			{ "Net No.", "simple.L16.net", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Net Number", HFILL }},

			{ &simple.link_16.hf.slot_count_2,
			{ "Sequential Slot Count – Field 2", "simple.L16.slot_count_2", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Sequential Slot Count – Field 2", HFILL }},

			{ &simple.link_16.hf.npg,
			{ "NPG No.", "simple.L16.npg", FT_UINT16, BASE_DEC, NULL, 0x0,
			"NPG", HFILL }},

			{ &simple.link_16.hf.slot_count_1,
			{ "Sequential Slot Count – Field 1", "simple.L16.slot_count_1", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Sequential Slot Count – Field 1", HFILL }},

			{ &simple.link_16.hf.stn,
			{ "STN", "simple.L16.stn", FT_UINT16, BASE_NONE, NULL, 0x0,
			"STN", HFILL }},

			{ &simple.link_16.hf.word_count,
			{ "Word Count", "simple.L16.word_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Word Count", HFILL }},

			{ &simple.link_16.hf.loopback_id,
			{ "Loopback ID", "simple.L16.loopback_id", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Loopback ID", HFILL }},

			{ &simple.link_16.hf.data,
			{ "Data", "simple.L16.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message L16", HFILL }} 			
		}//info
	},
	{//L11 
		{ -1, -1, -1, -1,  -1 },// hf
		{ -1, -1, -1, -1,  -1 },// ett
		{
			{ &simple.link_11.hf.id,
			{ "L11", "simple.L11", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet L11", HFILL }},

			{ &simple.link_11.hf.subtype,
			{ "Sub-Type", "simple.L11.subtype", FT_UINT8, BASE_DEC, VALS(SimpleLibelleL16SubType), 0x0,
			"Sub-Type", HFILL }},

			{ &simple.link_11.hf.pu,
			{ "STN", "simple.L11.pu", FT_UINT16, BASE_NONE, NULL, 0x0,
			"PU", HFILL }},

			{ &simple.link_11.hf.word_count,
			{ "Word Count", "simple.L11.word_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Word Count", HFILL }},

			{ &simple.link_11.hf.sequence_number,
			{ "Sequence Number", "simple.L11.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Sequence Number", HFILL }},

			{ &simple.link_11.hf.data,
			{ "Data", "simple.L11.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message L11", HFILL }} 			
		}//info
	},
	{//L11b 
		{ -1, -1, -1, -1},// hf
		{ -1, -1, -1, -1 },// ett
		{
			{ &simple.link_11b.hf.id,
			{ "L11b", "simple.L11b", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet L11b", HFILL }},

			{ &simple.link_11b.hf.destination_pu,
			{ "Destination PU Number", "simple.L11b.destination_pu", FT_UINT16, BASE_NONE, NULL, 0x0,
			"Destination PU Number", HFILL }},

			{ &simple.link_11b.hf.source_pu,
			{ "Source PU Number", "simple.L11b.source_pu", FT_UINT16, BASE_NONE, NULL, 0x0,
			"Source PU Number", HFILL }},

			{ &simple.link_11b.hf.word_count,
			{ "Word Count", "simple.L11b.word_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Word Count", HFILL }},


			{ &simple.link_11b.hf.data,
			{ "Data", "simple.L11b.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message L11b", HFILL }} 			
		}//info
	},
	{//DIS 
		{ -1, -1},// hf
		{ -1, -1},// ett
		{
			{ &simple.dis.hf.id,
			{ "DIS", "simple.DIS", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet DIS", HFILL }},

			{ &simple.dis.hf.data,
			{ "Data", "simple.DIS.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message DIS", HFILL }} 			
		}//info
	},
	{//PACKET TYPE (61) - STATUS/CONFIGURATION -NODE STATUS MESSAGE - 1 -
		{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},// hf
		{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},// ett
		{
			{ &simple.node_status.hf.id,
			{ "NODE STATUS MESSAGE", "simple.node_status", FT_NONE, BASE_NONE, NULL, 0x0,
			" NODE STATUS MESSAGE", HFILL }},

			{ &simple.node_status.hf.subtype,
			{ "Message Subtype", "simple.node_status.subtype", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Message Subtype", HFILL }},

			{ &simple.node_status.hf.number_of_words,
			{ "Number of Words", "simple.node_status.number_of_words", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of Words", HFILL }},

			{ &simple.node_status.hf.name,
			{ "SIMPLE Name", "simple.node_status.name", FT_STRING, BASE_NONE, NULL, 0x0,
			"Word Count", HFILL }},

			{ &simple.node_status.hf.node_id,
			{ "Simple Node ID", "simple.node_status.node_id", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Simple Node ID", HFILL }},

			{ &simple.node_status.hf.hours,
			{ "Time (Hours)", "simple.node_status.hours", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Time (Hours)", HFILL }},

			{ &simple.node_status.hf.minutes,
			{ "Time (Minutes))", "simple.node_status.minutes", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Time (Minutes))", HFILL }},

			{ &simple.node_status.hf.secondes,
			{ "Time (Seconds))", "simple.node_status.secondes", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Time (Seconds))", HFILL }},

			{ &simple.node_status.hf.security_level,
			{ "Security Level", "simple.node_status.security_level", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSecurityLevel), 0x0,
			"Security Level", HFILL }},

			{ &simple.node_status.hf.node_entry,
			{ "Node Entry Flag", "simple.node_status.node_entry", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Node Entry Flag", HFILL }},

			{ &simple.node_status.hf.relay_hope_node,
			{ "Relay Hop", "simple.node_status.relay_hope_node", FT_BYTES, BASE_DEC, NULL, 0x0,
			"Relay Hop", HFILL }},

			{ &simple.node_status.hf.DX,
			{ "Data Extraction (DX)", "simple.node_status.DX", FT_UINT16, BASE_OCT, NULL, 0x0,
			"Data Extraction (DX)", HFILL }},

			{ &simple.node_status.hf.DX_file_id,
			{ "Data Extraction (DX)", "simple.node_status.DX_file_id", FT_NONE, BASE_NONE, NULL, 0x0,
			"Data Extraction (DX)", HFILL }},

			{ &simple.node_status.hf.mids_jtids_terminal_type,
			{ "MIDS/JTIDS Terminal Type", "simple.node_status.mids_jtids_terminal_type", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_terminal_type), 0x0,
			"MIDS/JTIDS Terminal Type", HFILL }},

			{ &simple.node_status.hf.mids_jtids_role,
			{ "MIDS/JTIDS Role", "simple.node_status.mids_jtids_role", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_role), 0x0,
			"MIDS/JTIDS Role", HFILL }},

			{ &simple.node_status.hf.mids_jtids_terminal_host_status,
			{ "MIDS/JTIDS Terminal/Host Status", "simple.node_status.mids_jtids_terminal_host_status", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_terminal_host_status), 0x0,
			"MIDS/JTIDS Terminal/Host Status", HFILL }},

			{ &simple.node_status.hf.mids_jtids_synch_status,
			{ "MIDS/JTIDS Synch Status", "simple.node_status.mids_jtids_synch_status", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_sync_status), 0x0,
			"MIDS/JTIDS Synch Status", HFILL }},

			{ &simple.node_status.hf.mids_jtids_stn,
			{ "MIDS/JTIDS STN", "simple.node_status.mids_jtids_stn", FT_UINT8, BASE_DEC, NULL, 0x0,
			"MIDS/JTIDS STN", HFILL }},

			{ &simple.node_status.hf.link11_dts_type,
			{ "LINK-11 DTS Type", "simple.node_status.link11_dts_type", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l11_dts_type), 0x0,
			"LINK-11 DTS Type", HFILL }},

			{ &simple.node_status.hf.link11_role,
			{ "LINK-11 Role", "simple.node_status.link11_role", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l11_role), 0x0,
			"LINK-11 Role", HFILL }},

			{ &simple.node_status.hf.link11_pu,
			{ "LINK-11 PU Number", "simple.node_status.link11_pu", FT_UINT8, BASE_DEC, NULL, 0x0,
			"LINK-11 PU Number", HFILL }},

			{ &simple.node_status.hf.link11_dts_host_status,
			{ "LINK-11 DTS/Host Status", "simple.node_status.link11_dts_host_status", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l11_status), 0x0,
			"LINK-11 DTS/Host Status", HFILL }},


		}//info
	},
	{//PACKET TYPE (63) - ROUND TRIP TIMING (RTT) 
		{ -1, -1 ,-1, -1},// hf
		{ -1, -1, -1, -1},// ett
		{
			{ &simple.rtt.hf.id,
			{ "RTT", "simple.rtt", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet RTT", HFILL }},

			{ &simple.rtt.hf.node,
			{ "Originating SIMPLE ID", "simple.rtt.node", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Originating SIMPLE ID", HFILL }},
			
			{ &simple.rtt.hf.port,
			{ "Port ID", "simple.rtt.port", FT_UINT8, BASE_DEC, NULL, 0x0,
			"PortID", HFILL }},
			
			{ &simple.rtt.hf.time_stamp,
			{ "UTC Time Stamp", "simple.rtt.time_stamp", FT_UINT16, BASE_DEC, NULL, 0x0,
			"UTC Time Stamp", HFILL }},
			
		}//info
	},
	{//PACKET TYPE (65) - TIME SYNCHRONISATION 
		{ -1, -1 ,-1, -1},// hf
		{ -1, -1, -1, -1},// ett
		{
			{ &simple.time_synchro.hf.id,
			{ "TIME SYNCHRONISATION", "simple.time_synchro", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet TIME SYNCHRONISATION", HFILL }},

			{ &simple.time_synchro.hf.node,
			{ "Originating SIMPLE ID", "simple.time_synchro.node", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Originating SIMPLE ID", HFILL }},
			
			{ &simple.time_synchro.hf.utc,
			{ "UTC Time Stamp",	"simple.time_synchro.hf.utc", FT_UINT8, BASE_DEC, NULL, 0x0,
			"UTC Time Stamp", HFILL }},

			{ &simple.time_synchro.hf.exercise_offset,
			{ "Exercise Offset", "simple.time_synchro.exercise_offset", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Exercise Offset", HFILL }}
		}//info
	}
};
//	{//ett[]
//			&simple.network.ett.id;
//			&simple.network.ett.header;
//			&simple.network.ett.length;
//			&simple.network.ett.sequence;
//			&simple.network.ett.data;
//			&simple.network.ett.checksum;	
//
//			&simple.packet.ett.id;	
//			&simple.packet.ett.source_node;
//			&simple.packet.ett.source_subnode;
//			&simple.packet.ett.destination_node;
//			&simple.packet.ett.destination_subnode;
//			&simple.packet.ett.size;
//			&simple.packet.ett.type;
//			&simple.packet.ett.transit_time;
//			&simple.packet.ett.data;
//
//			&simple.link_16.ett.id;	
//			&simple.link_16.ett.subtype;
//			&simple.link_16.ett.rc_flag;
//			&simple.link_16.ett.net;
//			&simple.link_16.ett.slot_count_2;
//			&simple.link_16.ett.npg;
//			&simple.link_16.ett.slot_count_1;
//			&simple.link_16.ett.stn;
//			&simple.link_16.ett.word_count;
//			&simple.link_16.ett.loopback_id;
//			&simple.link_16.ett.data;
//
//			&simple.link_11.ett.id;	
//			&simple.link_11.ett.subtype;
//			&simple.link_11.ett.pu;
//			&simple.link_11.ett.sequence_number;
//			&simple.link_11.ett.word_count;
//			&simple.link_11.ett.data;	
//
//			&simple.link_11b.ett.id;	
//			&simple.link_11b.ett.destination_pu;
//			&simple.link_11b.ett.source_pu;
//			&simple.link_11b.ett.word_count;
//			&simple.link_11b.ett.data;
//
//			&simple.dis.ett.id;	
//			&simple.dis.ett.data;
//
//			&simple.node_status.ett.id;	
//			&simple.node_status.ett.subtype;
//			&simple.node_status.ett.number_of_words;
//			&simple.node_status.ett.name;
//			&simple.node_status.ett.node_id;
//			&simple.node_status.ett.hours;
//			&simple.node_status.ett.minutes;
//			&simple.node_status.ett.secondes;
//			&simple.node_status.ett.security_level;
//			&simple.node_status.ett.node_entry;
//			&simple.node_status.ett.relay_hope_node;
//			&simple.node_status.ett.DX;
//			&simple.node_status.ett.DX_file_id;
//			&simple.node_status.ett.mids_jtids_role;
//			&simple.node_status.ett.mids_jtids_terminal_type;
//			&simple.node_status.ett.mids_jtids_terminal_host_status;
//			&simple.node_status.ett.mids_jtids_synch_status;
//			&simple.node_status.ett.mids_jtids_stn;
//			&simple.node_status.ett.link11_dts_type;
//			&simple.node_status.ett.link11_role;
//			&simple.node_status.ett.link11_pu;
//			&simple.node_status.ett.link11_dts_host_status;
//
//			&simple.rtt.ett.id;	
//			&simple.rtt.ett.node;
//			&simple.rtt.ett.port;
//			&simple.rtt.ett.time_stamp;
//
//			&simple.time_synchro.ett.id;	
//			&simple.time_synchro.ett.node;
//			&simple.time_synchro.ett.utc;
//			&simple.time_synchro.ett.exercise_offset;
//	}
//};
//	{//hf[]
//			&simple.network.ett.id;
//			&simple.network.ett.header;
//			&simple.network.ett.length;
//			&simple.network.ett.sequence;
//			&simple.network.ett.data;
//			&simple.network.ett.checksum;	
//
//			&simple.packet.ett.id;	
//			&simple.packet.ett.source_node;
//			&simple.packet.ett.source_subnode;
//			&simple.packet.ett.destination_node;
//			&simple.packet.ett.destination_subnode;
//			&simple.packet.ett.size;
//			&simple.packet.ett.type;
//			&simple.packet.ett.transit_time;
//			&simple.packet.ett.data;
//
//			&simple.link_16.ett.id;	
//			&simple.link_16.ett.subtype;
//			&simple.link_16.ett.rc_flag;
//			&simple.link_16.ett.net;
//			&simple.link_16.ett.slot_count_2;
//			&simple.link_16.ett.npg;
//			&simple.link_16.ett.slot_count_1;
//			&simple.link_16.ett.stn;
//			&simple.link_16.ett.word_count;
//			&simple.link_16.ett.loopback_id;
//			&simple.link_16.ett.data;
//
//			&simple.link_11.ett.id;	
//			&simple.link_11.ett.subtype;
//			&simple.link_11.ett.pu;
//			&simple.link_11.ett.sequence_number;
//			&simple.link_11.ett.word_count;
//			&simple.link_11.ett.data;	
//
//			&simple.link_11b.ett.id;	
//			&simple.link_11b.ett.destination_pu;
//			&simple.link_11b.ett.source_pu;
//			&simple.link_11b.ett.word_count;
//			&simple.link_11b.ett.data;
//
//			&simple.dis.ett.id;	
//			&simple.dis.ett.data;
//
//			&simple.node_status.ett.id;	
//			&simple.node_status.ett.subtype;
//			&simple.node_status.ett.number_of_words;
//			&simple.node_status.ett.name;
//			&simple.node_status.ett.node_id;
//			&simple.node_status.ett.hours;
//			&simple.node_status.ett.minutes;
//			&simple.node_status.ett.secondes;
//			&simple.node_status.ett.security_level;
//			&simple.node_status.ett.node_entry;
//			&simple.node_status.ett.relay_hope_node;
//			&simple.node_status.ett.DX;
//			&simple.node_status.ett.DX_file_id;
//			&simple.node_status.ett.mids_jtids_role;
//			&simple.node_status.ett.mids_jtids_terminal_type;
//			&simple.node_status.ett.mids_jtids_terminal_host_status;
//			&simple.node_status.ett.mids_jtids_synch_status;
//			&simple.node_status.ett.mids_jtids_stn;
//			&simple.node_status.ett.link11_dts_type;
//			&simple.node_status.ett.link11_role;
//			&simple.node_status.ett.link11_pu;
//			&simple.node_status.ett.link11_dts_host_status;
//
//			&simple.rtt.ett.id;	
//			&simple.rtt.ett.node;
//			&simple.rtt.ett.port;
//			&simple.rtt.ett.time_stamp;
//
//			&simple.time_synchro.ett.id;	
//			&simple.time_synchro.ett.node;
//			&simple.time_synchro.ett.utc;
//			&simple.time_synchro.ett.exercise_offset;
//	}
//};
//

void initialisation_simple(T_SimpleData *simple )
{


}




void proto_reg_handoff_simple(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) 
	{
		initialisation_simple(&simple);

		data_handle   = find_dissector("data");
		simple_handle = create_dissector_handle(dissect_simple, proto_simple);
		dissector_add_uint("tcp.port", global_simple_port, simple_handle);
		dissector_add_uint("udp.port", global_simple_port, simple_handle);
	}
}

void proto_register_simple (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	{
		int i = 1;
		memcpy( &simple.hf(i++], &simple.network.hf,  C_Longueur_network*sizeof(hf_register_info));
		memcpy( &simple.hf(i++], &simple.packet.hf,  C_Longueur_packet*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.link_16.hf,  C_Longueur_link_16*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.link_11.hf,  C_Longueur_link_11*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.link_11b.hf,  C_Longueur_link_11b*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.dis.hf,  C_Longueur_dis*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.node_status.hf,  C_Longueur_node_status*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.rtt.hf,  C_Longueur_rtt*sizeof(hf_register_info);
		memcpy( &simple.hf(i++], &simple.time_synchro.hf,  C_Longueur_time_synchronisation*sizeof(hf_register_info);	
	}

	proto_simple = proto_register_protocol ("SIMPLE Protocol", "SIMPLE", "simple");

	proto_register_field_array (proto_simple, &simple.hf, array_length (simple->hf));
	proto_register_subtree_array (&simple.ett, array_length (simple->ett));
	register_dissector("simple", dissect_simple, proto_simple);
}

static void 
dissect_simple_decode_PDU(	proto_item *simple_item ,
							   proto_tree *simple_tree,
							   guint32 *offset)
{
	guint16 type     = 0;

	proto_item *simple_sub_item    = NULL;
	proto_tree *simple_packet_header_tree = NULL; 

	simple_header_tree = proto_item_add_subtree(simple_sub_item, ett_simple);


	tvb_memcpy(tvb, (guint16 *)&sequence, 2, 4);
	tvb_memcpy(tvb, (guint16 *)&checksum, length, 4);

	simple_item        = proto_tree_add_item(tree, proto_simple, tvb, 0, -1, ENC_NA);
	simple_tree        = proto_item_add_subtree(simple_item, ett_simple);
	simple_header_tree = proto_item_add_subtree(simple_item, ett_simple);

	*offset+=1;

	tvb_memcpy(tvb, (guint8 *)&type, *offset, 4);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIMPLE");

	if( type == 0 )
	{
		proto_tree_add_item( simple_tree, hf_simple_text, tvb, *offset, length-1, FALSE );
		*offset+=1;
	}
}

static void 
dissect_simple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	T_ProtocolePrive *mes_donnees = (T_ProtocolePrive *)data;

	guint16 header   = 0;
	guint16 length   = 0;
	guint16 sequence = 0;
	guint16 checksum = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SIMPLE);
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	header = tvb_get_guint8( tvb, 0 ); // Get the type byte
	tvb_memcpy(tvb, (guint16 *)&length, 0, 2);
	if (header==0x4936)
		col_add_fstr(pinfo->cinfo, COL_INFO, "Message  Simple %02d", length);
	else
		col_add_fstr(pinfo->cinfo, COL_INFO, "Message  Simple Entete inconnue 0x%04x",header);


	if (header && 0xff == 0x49)
		simple->encoding = ENC_BIG_ENDIAN;
	else if (header && 0xff == 0x49)
		simple->encoding = ENC_LIT_ENDIAN;
	else
		simple->encoding = ENC_NA;


	if (tree)
	{ /* we are being asked for details */
		proto_item *simple_item        = NULL;
		proto_item *simple_sub_item    = NULL;
		proto_tree *simple_tree        = NULL;
		proto_tree *simple_network_header_tree = NULL; 
		guint32 offset = 0;


	    tvb_memcpy(tvb, (guint16 *)&sequence, 2, 4);
	    tvb_memcpy(tvb, (guint16 *)&checksum, length, 4);

		simple_item        = proto_tree_add_item(tree, proto_simple, tvb, 0, -1, ENC_NA);
		simple_tree        = proto_item_add_subtree(simple_item, &simple.network.info);
		simple_header_tree = proto_item_add_subtree(simple_item, ett_simple);

		simple_sub_item    = proto_tree_add_item( simple_tree, hf_simple_header, tvb, offset, -1, FALSE );
		simple_header_tree = proto_item_add_subtree(simple_sub_item, ett_simple);

		tvb_memcpy(tvb, (guint8 *)&length, offset, 4);

		proto_tree_add_uint(simple_network_header_tree, hf_simple_header, tvb, offset, 4, length);
		offset+=4;

		proto_tree_add_uint(simple_network_header_tree, hf_simple_length, tvb, offset, 4, length);
		offset+=4;

		proto_tree_add_uint(simple_network_header_tree, hf_simple_sequence, tvb, offset, 4, length);
		offset+=4;

		dissect_simple_decode_PDU(	simple_item , simple_tree,	&offset);

		/** Type Byte */
		proto_tree_add_item(simple_network_header_tree, hf_simple_checksum, tvb, offset, 4, FALSE);

		
	}
}

