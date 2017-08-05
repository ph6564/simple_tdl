/* packet-simple.c
* Routines for simple message dissection (STANAG 5602)
* Initiated by Pierre-Henri BOURDELLE  <pierre-henri.bourdelle@orange.fr>
*
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
#include <epan/prefs.h>
//#include <epan/dissectors/packet-dis.h>
#include "packet-l16.h"
#include "packet-l11.h"
#include "dis_simple.h"


#include <string.h>
# include "simple.h"
#define PROTO_TAG_SIMPLE	"SIMPLE"
#define DEFAULT_SIMPLE_UDP_PORT 1111
#define DEFAULT_SIMPLE_TCP_PORT 1111

/* Wireshark ID of the SIMPLE protocol */
static int proto_simple = -1;
static int proto_dis = -1;



/* These are the handles of our subdissectors */
static dissector_handle_t l16_handle=NULL;
static dissector_handle_t link11_handle=NULL;
static dissector_handle_t dis_handle=NULL;
static dissector_table_t l16_dissector_table = NULL;
static dissector_table_t link11_dissector_table = NULL;
static dissector_table_t dis_dissector_table = NULL;
static dissector_handle_t simple_handle;
int dissect_simple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int global_simple_port = 1033;
static int global_dis_port = 10435;


const value_string simple_packettypenames[] = {
	{ 0, "Illegal" },
	{ 1, "Link 16" },
	{ 2, "Link 11" },
	{ 3, "Link 4" },
	{ 4, "Link 22" },
	{ 5, "Interim JTIDS Message Standard (IJMS)" },
	{ 6, "USA Messages" },
	{ 7, "USA Messages" },
	{ 8, "Variable Message Format (VMF)" },
	{ 9, "TIM/TOM Data" },
	{ 10, "MSTM Data" },
	{ 12, "TADIL PDU" },
	{ 13, "MIDS/JTIDS Voice" },
	{ 20, "Link 11B" },
	{ 30, "SIF Event Data" },
	{ 31, "SIF Event Data" },
	{ 32, "DIS Protocol Data Unit (PDU)" },
	{ 33, "TDSIU Events" },
	{ 34, "JITC SS Events" },
	{ 61, "Status Configuration" },		
	{ 62, "E-mail/File Transfer Protocol (FTP)" },
	{ 63, "Round Trip Timing (RTT)" },
	{ 64, "Gateway Voice" },
	{ 65, "Time Synchronisation" },
	{ 66, "TSA Status" },
	{ 100, "National Message" },
	{ 101, "USA Messages" },
	{ 0, NULL }
};	


/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_simple()
*/

enum  { 
	e_simple=0,
	e_packet_data,
	e_network,
	e_packet,
	e_link16, 
	e_link11, 
	e_link11b, 
	e_dis, 
	e_node_status, 
	e_rtt, 
	e_time_synchro,
    e_nombre_champs};
const int nombre_de_champs = (int)e_nombre_champs;

typedef struct ST_SimpleData
{
	guint encoding;
	struct 
	{
		struct 
		{
			gint id;
		}hf;
		struct 
		{
			gint id;
		}ett;
#define C_Longueur_simple		1
		hf_register_info info[C_Longueur_simple];
	}simple;
	struct 
	{
		struct 
		{
			gint id;
		}hf;
		struct 
		{
			gint id;
		}ett;
#define C_Longueur_packet_data		1
		hf_register_info info[C_Longueur_packet_data];
	}packet_data;
	
	struct 
	{
		struct 
		{
			gint id;
			gint synch_byte_1;
			gint synch_byte_2;
			gint length;
			gint sequence;
			gint data;
			gint checksum;

		}hf;
		struct 
		{
			gint id;
			gint synch_byte_1;
			gint synch_byte_2;
			gint length;
			gint sequence;
			gint data;
			gint checksum;
		}ett;
#define C_Longueur_network		7

		hf_register_info info[C_Longueur_network];
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
			gint segment_number;
			gint number_of_segments;
			gint data;
		}hf;
		struct 
		{
			gint id;
			gint segment_number;
			gint number_of_segments;
			gint data;
		}ett;
#define C_Longueur_dis	4
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
#define C_Longueur_node_status	22
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

	gint *ett[e_nombre_champs];
	hf_register_info hf[ C_Longueur_simple + C_Longueur_packet_data  + C_Longueur_network +  C_Longueur_packet +C_Longueur_link_16     
		                + C_Longueur_link_11 + C_Longueur_link_11b + C_Longueur_dis + C_Longueur_node_status + C_Longueur_rtt     + 
			            C_Longueur_time_synchro + 1];

}T_SimpleData;

static T_SimpleData s_simple= {
	//encoding
	ENC_NA,
	//simple 
	{
		{ -1},
		{ -1},
		{
			{ &s_simple.simple.hf.id,
			   { "Simple", "simple", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE", HFILL }
			}
		}
	},	
	//data 
	{
		{ -1},
		{ -1},
		{
			{ &s_simple.packet_data.hf.id,
			   { "Packet Data", "packet.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"PACKET  DATA", HFILL }
			}
		}
	},
    //network 
	{
		{ -1, -1, -1, -1,  -1, -1, -1},//network hf
		{ -1, -1, -1, -1,  -1, -1, -1},//network ett
		{
			{ &s_simple.network.hf.id,
			{ "Simple Network", "simple.network", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE network", HFILL }},

			{ &s_simple.network.hf.synch_byte_1,
			{ "Synch Byte 1", "simple.network.synch_byte_1", FT_UINT8, BASE_HEX, NULL, 0x0,
			"SIMPLE Header", HFILL }},

			{ &s_simple.network.hf.synch_byte_2,
			{ "Synch Byte 2", "simple.network.synch_byte_2", FT_UINT8, BASE_HEX, NULL, 0x0,
			"SIMPLE Header", HFILL }},

			{ &s_simple.network.hf.length,
			{ "SIMPLE Length", "simple.network.len", FT_UINT16, BASE_DEC, NULL, 0x0,
			"SIMPLE Length", HFILL }},

			{ &s_simple.network.hf.sequence,
			{ "SIMPLE Sequence", "simple.network.sequence", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Sequence Numbre by Node", HFILL }},	

			{ &s_simple.network.hf.data,
			{ "Network Data", "simple.network.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"data", HFILL }},

			{ &s_simple.network.hf.checksum,
			{ "Checksum", "simple.network.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
			"checksum", HFILL }}
		}//info
	},
	//packet 
	{
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1 },// hf
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1 },// ett
		{
			{ &s_simple.packet.hf.id,
			{ "Packet", "simple.packet", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet", HFILL }},

			{ &s_simple.packet.hf.source_node,
			{ "Source Node", "simple.packet.source_node", FT_UINT8, BASE_DEC, VALS(SimpleLibelleNode), 0x0,
			"Source Node", HFILL }},

			{ &s_simple.packet.hf.source_subnode,
			{ "Source Subnode", "simple.packet.source_subnode", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSubNode), 0x0,
			"Source Subnode", HFILL }},

			{ &s_simple.packet.hf.destination_node,
			{ "Destination Node", "simple.packet.destination_node", FT_UINT8, BASE_DEC, VALS(SimpleLibelleNode), 0x0,
			"Destination Node", HFILL }},

			{ &s_simple.packet.hf.destination_subnode,
			{ "Destination Subnode", "simple.packet.destination_subnode", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSubNode), 0x0,
			"Destination Subnode", HFILL }},

			{ &s_simple.packet.hf.size,
			{ "Packet Size", "simple.packet.size", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Packet Size", HFILL }},

			{ &s_simple.packet.hf.type,
			{ "Type", "simple.packet.type", FT_UINT8, BASE_DEC, VALS(simple_packettypenames), 0x0,
			"Simple Packet Type", HFILL }}, 

			{ &s_simple.packet.hf.transit_time,
			{ "Transit Time", "simple.packet.transit_time", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Packet Transit Time", HFILL }},

			{ &s_simple.packet.hf.data,
			{ "Packet Data", "simple.packet.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Simple Packet Data", HFILL }} 			
		}//info
	},
	//L16 
	{
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1, -1,  -1 },// hf
		{ -1, -1, -1, -1,  -1, -1, -1,  -1, -1, -1,  -1 },// ett
		{
			{ &s_simple.link_16.hf.id,
			{ "L16", "simple.L16", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet L16", HFILL }},

			{ &s_simple.link_16.hf.subtype,
			{ "Sub-Type", "simple.L16.subtype", FT_UINT8, BASE_DEC, VALS(SimpleLibelleL16SubType), 0x0,
			"Sub-Type", HFILL }},

			{ &s_simple.link_16.hf.rc_flag,
			{ "R/C Flag", "simple.L16.rc_flag", FT_UINT8, BASE_DEC, NULL, 0x0,
			"R/C Flag", HFILL }},

			{ &s_simple.link_16.hf.net,
			{ "Net No.", "simple.L16.net", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Net Number", HFILL }},

			{ &s_simple.link_16.hf.slot_count_2,
			{ "Sequential Slot Count Field 2", "simple.L16.slot_count_2", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Sequential Slot Count Field 2", HFILL }},

			{ &s_simple.link_16.hf.npg,
			{ "NPG No.", "simple.L16.npg", FT_UINT16, BASE_DEC, NULL, 0x0,
			"NPG", HFILL }},

			{ &s_simple.link_16.hf.slot_count_1,
			{ "Sequential Slot Count Field 1", "simple.L16.slot_count_1", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Sequential Slot Count Field 1", HFILL }},

			{ &s_simple.link_16.hf.stn,
			{ "STN", "simple.L16.stn", FT_UINT16, BASE_DEC, NULL, 0x0,
			"STN", HFILL }},

			{ &s_simple.link_16.hf.word_count,
			{ "Word Count", "simple.L16.word_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Word Count", HFILL }},

			{ &s_simple.link_16.hf.loopback_id,
			{ "Loopback ID", "simple.L16.loopback_id", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Loopback ID", HFILL }},

			{ &s_simple.link_16.hf.data,
			{ "Data", "simple.L16.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message L16", HFILL }} 			
		}//info
	},
	{//L11 
		{ -1, -1, -1, -1, -1, -1 },// hf
		{ -1, -1, -1, -1, -1, -1 },// ett
		{
			{ &s_simple.link_11.hf.id,
			{ "L11", "simple.L11", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet L11", HFILL }},

			{ &s_simple.link_11.hf.subtype,
			{ "Sub-Type", "simple.L11.subtype", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSubtypeL11), 0x0,
			"Sub-Type", HFILL }},

			{ &s_simple.link_11.hf.pu,
			{ "STN", "simple.L11.pu", FT_UINT16, BASE_DEC, NULL, 0x0,
			"PU", HFILL }},

			{ &s_simple.link_11.hf.word_count,
			{ "Word Count", "simple.L11.word_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Word Count", HFILL }},

			{ &s_simple.link_11.hf.sequence_number,
			{ "Sequence Number", "simple.L11.sequence_number", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Sequence Number", HFILL }},

			{ &s_simple.link_11.hf.data,
			{ "Data", "simple.L11.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message L11", HFILL }} 			
		}//info
	},
	{//L11b 
		{ -1, -1, -1, -1, -1},// hf
		{ -1, -1, -1, -1, -1 },// ett
		{
			{ &s_simple.link_11b.hf.id,
			{ "L11b", "simple.L11b", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet L11b", HFILL }},

			{ &s_simple.link_11b.hf.destination_pu,
			{ "Destination PU Number", "simple.L11b.destination_pu", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Destination PU Number", HFILL }},

			{ &s_simple.link_11b.hf.source_pu,
			{ "Source PU Number", "simple.L11b.source_pu", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Source PU Number", HFILL }},

			{ &s_simple.link_11b.hf.word_count,
			{ "Word Count", "simple.L11b.word_count", FT_UINT16, BASE_DEC, NULL, 0x0,
			"Word Count", HFILL }},


			{ &s_simple.link_11b.hf.data,
			{ "Data", "simple.L11b.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message L11b", HFILL }} 			
		}//info
	},
	{//DIS 
		{ -1, -1, -1, -1},// hf
		{ -1, -1, -1, -1},// ett
		{
			{ &s_simple.dis.hf.id,
			{ "DIS", "simple.dis", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet DIS", HFILL }},

			{ &s_simple.dis.hf.segment_number,
			{ "Segment number", "simple.dis.segment_number", FT_UINT8, BASE_DEC, NULL, 0x0,
			"segment number", HFILL }},

			{ &s_simple.dis.hf.number_of_segments,
			{ "Number of Segments", "simple.dis.number_of_segments", FT_UINT8, BASE_DEC, NULL, 0x0,
			"number of segments", HFILL }},

			{ &s_simple.dis.hf.data,
			{ "Data", "simple.dis.data", FT_NONE, BASE_NONE, NULL, 0x0,
			"Message DIS", HFILL }} 			
		}//info
	},
	{//PACKET TYPE (61) - STATUS/CONFIGURATION -NODE STATUS MESSAGE - 1 -
		{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},// hf
		{ -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},// ett
		{
			{ &s_simple.node_status.hf.id,
			{ "NODE STATUS MESSAGE", "simple.node_status", FT_NONE, BASE_NONE, NULL, 0x0,
			" NODE STATUS MESSAGE", HFILL }},

			{ &s_simple.node_status.hf.subtype,
			{ "Message Subtype", "simple.node_status.subtype", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Message Subtype", HFILL }},

			{ &s_simple.node_status.hf.number_of_words,
			{ "Number of Words", "simple.node_status.number_of_words", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of Words", HFILL }},

			{ &s_simple.node_status.hf.name,
			{ "SIMPLE Name", "simple.node_status.name", FT_STRING, BASE_NONE, NULL, 0x0,
			"Word Count", HFILL }},

			{ &s_simple.node_status.hf.node_id,
			{ "Simple Node ID", "simple.node_status.node_id", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Simple Node ID", HFILL }},

			{ &s_simple.node_status.hf.hours,
			{ "Time (Hours)", "simple.node_status.hours", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Time (Hours)", HFILL }},

			{ &s_simple.node_status.hf.minutes,
			{ "Time (Minutes))", "simple.node_status.minutes", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Time (Minutes))", HFILL }},

			{ &s_simple.node_status.hf.secondes,
			{ "Time (Seconds))", "simple.node_status.secondes", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Time (Seconds))", HFILL }},

			{ &s_simple.node_status.hf.security_level,
			{ "Security Level", "simple.node_status.security_level", FT_UINT8, BASE_DEC, VALS(SimpleLibelleSecurityLevel), 0x0,
			"Security Level", HFILL }},

			{ &s_simple.node_status.hf.node_entry,
			{ "Node Entry Flag", "simple.node_status.node_entry", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Node Entry Flag", HFILL }},

			{ &s_simple.node_status.hf.relay_hope_node,
			{ "Relay Hop", "simple.node_status.relay_hope_node", FT_BYTES, BASE_NONE, NULL, 0x0,
			"Relay Hop", HFILL }},

			{ &s_simple.node_status.hf.DX,
			{ "Data Extraction (DX)", "simple.node_status.DX", FT_UINT16, BASE_OCT, NULL, 0x0,
			"Data Extraction (DX)", HFILL }},

			{ &s_simple.node_status.hf.DX_file_id,
			{ "Data Extraction File ID(DX)", "simple.node_status.DX_file_id", FT_NONE, BASE_NONE, NULL, 0x0,
			"Data Extraction File ID (DX)", HFILL }},

			{ &s_simple.node_status.hf.mids_jtids_terminal_type,
			{ "MIDS/JTIDS Terminal Type", "simple.node_status.mids_jtids_terminal_type", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_terminal_type), 0x0,
			"MIDS/JTIDS Terminal Type", HFILL }},

			{ &s_simple.node_status.hf.mids_jtids_role,
			{ "MIDS/JTIDS Role", "simple.node_status.mids_jtids_role", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_role), 0x0,
			"MIDS/JTIDS Role", HFILL }},

			{ &s_simple.node_status.hf.mids_jtids_terminal_host_status,
			{ "MIDS/JTIDS Terminal/Host Status", "simple.node_status.mids_jtids_terminal_host_status", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_terminal_host_status), 0x0,
			"MIDS/JTIDS Terminal/Host Status", HFILL }},

			{ &s_simple.node_status.hf.mids_jtids_synch_status,
			{ "MIDS/JTIDS Synch Status", "simple.node_status.mids_jtids_synch_status", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l16_sync_status), 0x0,
			"MIDS/JTIDS Synch Status", HFILL }},

			{ &s_simple.node_status.hf.mids_jtids_stn,
			{ "MIDS/JTIDS STN", "simple.node_status.mids_jtids_stn", FT_UINT8, BASE_DEC, NULL, 0x0,
			"MIDS/JTIDS STN", HFILL }},

			{ &s_simple.node_status.hf.link11_dts_type,
			{ "LINK-11 DTS Type", "simple.node_status.link11_dts_type", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l11_dts_type), 0x0,
			"LINK-11 DTS Type", HFILL }},

			{ &s_simple.node_status.hf.link11_role,
			{ "LINK-11 Role", "simple.node_status.link11_role", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l11_role), 0x0,
			"LINK-11 Role", HFILL }},

			{ &s_simple.node_status.hf.link11_pu,
			{ "LINK-11 PU Number", "simple.node_status.link11_pu", FT_UINT8, BASE_DEC, NULL, 0x0,
			"LINK-11 PU Number", HFILL }},

			{ &s_simple.node_status.hf.link11_dts_host_status,
			{ "LINK-11 DTS/Host Status", "simple.node_status.link11_dts_host_status", FT_UINT8, BASE_DEC, VALS(SimpleLibelle_l11_status), 0x0,
			"LINK-11 DTS/Host Status", HFILL }},


		}//info
	},
	{//PACKET TYPE (63) - ROUND TRIP TIMING (RTT) 
		{ -1, -1 ,-1, -1},// hf
		{ -1, -1, -1, -1},// ett
		{
			{ &s_simple.rtt.hf.id,
			{ "RTT", "simple.rtt", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet RTT", HFILL }},

			{ &s_simple.rtt.hf.node,
			{ "Originating SIMPLE ID", "simple.rtt.node", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Originating SIMPLE ID", HFILL }},
			
			{ &s_simple.rtt.hf.port,
			{ "Port ID", "simple.rtt.port", FT_UINT8, BASE_DEC, NULL, 0x0,
			"PortID", HFILL }},
			
			{ &s_simple.rtt.hf.time_stamp,
			{ "UTC Time Stamp", "simple.rtt.time_stamp", FT_UINT16, BASE_DEC, NULL, 0x0,
			"UTC Time Stamp", HFILL }},
			
		}//info
	},
	{//PACKET TYPE (65) - TIME SYNCHRONISATION 
		{ -1, -1 ,-1, -1},// hf
		{ -1, -1, -1, -1},// ett
		{
			{ &s_simple.time_synchro.hf.id,
			{ "TIME SYNCHRONISATION", "simple.time_synchro", FT_NONE, BASE_NONE, NULL, 0x0,
			"SIMPLE packet TIME SYNCHRONISATION", HFILL }},

			{ &s_simple.time_synchro.hf.node,
			{ "Originating SIMPLE ID", "simple.time_synchro.node", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Originating SIMPLE ID", HFILL }},
			
			{ &s_simple.time_synchro.hf.utc,
			{ "UTC Time Stamp",	"simple.time_synchro.hf.utc", FT_UINT8, BASE_DEC, NULL, 0x0,
			"UTC Time Stamp", HFILL }},

			{ &s_simple.time_synchro.hf.exercise_offset,
			{ "Exercise Offset", "simple.time_synchro.exercise_offset", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Exercise Offset", HFILL }}
		}//info
	}
};

typedef struct ST_ProtocoleSimplePrive
{
	T_SimpleData *simple;
	int proto_simple;/* Wireshark ID of the SIMPLE protocol */
	int type;
	Link16State link16_state;
	DISState    dis_state;
	L11State    link11_state;
}T_ProtocoleSimplePrive;
static T_ProtocoleSimplePrive s_SimplePrive= { &s_simple, 0,0};

static guint dis_udp_port = DEFAULT_SIMPLE_UDP_PORT;
static guint dis_tcp_port = DEFAULT_SIMPLE_TCP_PORT;
		 
static int LettresTN[32]=
{
'0','1','2','3','4','5','6','7','A','B','C','D','E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W','X','Y','Z',
};
static int ChiffresTN[36]=
{
/*==========================================================================================================*/
/*0  1  2  3  4  5  6  7  A  B  C  D  E  F  G  H  J  K  L  M   N  P  Q  R  S  T  U  V  W  X  Y  Z*/
/*==========================================================================================================*/
  0, 1 ,2 ,3 ,4 ,5 ,6 ,7, 8 ,9, 10,11,12,13,14,15,16,17,18,19,20, 21,22,23,24,25,26,27,28,29,30,31
};

static char * traduire_numero_piste(unsigned long numero_piste, char *s)
{
   unsigned int numero1 = numero_piste & 07;
   unsigned int numero2 = (numero_piste & 070)>>3;
   unsigned int numero3 = (numero_piste & 0700)>>6;
   unsigned int numero4 = (int)(numero_piste/ 512) & 037;
   unsigned int numero5 = (int)(numero_piste/ 16384) & 037; 


   if (numero_piste <= 0xFFFFFF)
   {
      s[4]=LettresTN[numero1]; 
      s[3]=LettresTN[numero2];
      s[2]=LettresTN[numero3];
      s[1]=LettresTN[numero4];
      s[0]=LettresTN[numero5];
      s[5]='\0'; 
   }
   else
   {
      s[4]='#'; 
      s[3]='#'; 
      s[2]='#'; 
      s[1]='#'; 
      s[0]='#'; 
      s[5]='\0'; 
}
      

   return (s);
}


void proto_reg_handoff_simple(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {

		simple_handle = create_dissector_handle(dissect_simple, proto_simple);
		dissector_add_uint("tcp.port", global_simple_port, simple_handle);
		dissector_add_uint("udp.port", global_simple_port, simple_handle);
	}

	if (!dis_handle)
	{
		dis_handle  = find_dissector("dis_simple");
	}
	if (!l16_handle)
			l16_handle  = find_dissector("l16");
	if (!link11_handle)
			link11_handle  = find_dissector("l11");
}

#pragma optimize("", off)
 

void proto_register_simple (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	{
		int nombre_hf = 0, nombre_ett = 0, nombre = 0;
		hf_register_info *hf = s_simple.hf;
   
		module_t *simple_module;
		
		nombre = sizeof(s_simple.simple.info)/sizeof(hf_register_info);
		memcpy( (void *)(&hf[nombre_hf]),&s_simple.simple.info,  sizeof(s_simple.simple.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.packet_data.info)/sizeof(hf_register_info);
		memcpy( (void *)(&hf[nombre_hf]),&s_simple.packet_data.info,  sizeof(s_simple.packet_data.info));
		nombre_hf += nombre;


		nombre = sizeof(s_simple.network.info)/sizeof(hf_register_info);
		memcpy( (void *)(&hf[nombre_hf]),&s_simple.network.info,  sizeof(s_simple.network.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.packet.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.packet.info,  sizeof(s_simple.packet.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.link_16.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.link_16.info,  sizeof(s_simple.link_16.info));
		nombre_hf += nombre;


		nombre = sizeof(s_simple.link_11.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.link_11.info, sizeof(s_simple.link_11.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.link_11b.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.link_11b.info,  sizeof(s_simple.link_11b.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.dis.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.dis.info,  sizeof(s_simple.dis.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.node_status.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.node_status.info,  sizeof(s_simple.node_status.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.rtt.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.rtt.info, sizeof(s_simple.rtt.info));
		nombre_hf += nombre;

		nombre = sizeof(s_simple.time_synchro.info)/sizeof(hf_register_info);
		memcpy( &hf[nombre_hf], &s_simple.time_synchro.info,  sizeof(s_simple.time_synchro.info));
		nombre_hf += nombre;
		
		s_simple.ett[nombre_ett++]= &s_simple.simple.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.packet_data.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.network.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.packet.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.link_16.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.link_11.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.link_11b.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.dis.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.node_status.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.rtt.ett.id;
		s_simple.ett[nombre_ett++]= &s_simple.time_synchro.ett.id;

		proto_simple = proto_register_protocol ("SIMPLE Protocol", "SIMPLE", "simple");

		proto_register_field_array (proto_simple, s_simple.hf, nombre_hf);
		proto_register_subtree_array (s_simple.ett, nombre_ett);

		
		simple_module = prefs_register_protocol(proto_simple, proto_reg_handoff_simple);

		/* create an unsigned integer preference to allow the user to specify the
		* udp port on which to capture dis packets.
		*/
		prefs_register_uint_preference(simple_module, "udp.port",
			"simple udp port",
			"set the udp port for simple messages",
			10, &dis_udp_port);
		prefs_register_uint_preference(simple_module, "tcp.port",
			"simple tcp port",
			"set the tcp port for simple messages",
			10, &dis_tcp_port);


		register_dissector("simple", dissect_simple, proto_simple);

	}


}

#pragma optimize("", on)

static int 
dissect_simple(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	T_ProtocoleSimplePrive *prive;
    T_SimpleData *simple;
	guint16 header   = 0;
	guint16 length   = 0;
	guint16 donnee16   = 0;
	guint8  donnee8   = 0;
	guint32  donnee32   = 0;
	guint64  donnee64   = 0;
	int encoding =0;
	int t =0;
	int type=0 ;
	static stn_s[6];
	const int c_increment8  =1;
	const int c_increment16 =2;
	const int c_increment32 =4;

	prive = &s_SimplePrive;

	simple = prive->simple;



	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SIMPLE);
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	tvb_memcpy(tvb, (guint16 *)&header, 0, 2);
	tvb_memcpy(tvb, (guint16 *)&length, 2, 2);


	if ((header & 0xff) == 0x49)
	{
		simple->encoding = ENC_BIG_ENDIAN;
	    prive->dis_state.encoding = simple->encoding ;
		encoding = 1;
	}
	else if ((header & 0xff) == 0x36)
	{
		simple->encoding = ENC_LITTLE_ENDIAN ;
	    prive->dis_state.encoding = simple->encoding ;
		encoding = 2;
	}
	else
	{
		simple->encoding = ENC_NA;
	    prive->dis_state.encoding = ENC_BIG_ENDIAN ;
		encoding = 3;
	}

	t = length;
	
	tvb_memcpy(tvb, &donnee8, 11, 1);
	prive->type = type =(int)(donnee8&0xff);

	if (header==0x4936 || header==0x3649 )
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s - %s Len=%02d", val_to_str(type, simple_packettypenames, "Unknown (0x%03d)"), simple->encoding==ENC_LITTLE_ENDIAN?"LE":"BE", t);
	else
		col_add_fstr(pinfo->cinfo, COL_INFO, " Entete inconnue 0x%04x",header);

	if (!tree)
	{
		if (type==e_Link16_type)
		{
			char info[255];
			long stn, npg;

			tvb_memcpy(tvb, &donnee16, 18, c_increment16);npg = (long)prive->link16_state.header.npg = (int)(donnee16&0xffff);
			tvb_memcpy(tvb, &donnee16, 22, c_increment16);stn = (long)prive->link16_state.header.stn = (int)(donnee16&0xffff);
			col_add_fstr(pinfo->cinfo, COL_INFO, "Link 16 - IU:%s - NPG:%d - %s Len=%02d",
				traduire_numero_piste((long)(donnee8&0xff), info),npg, 
				simple->encoding==ENC_LITTLE_ENDIAN?"LE":"BE", t);
		}
		if (type==e_Link11_type)
		{
			char info[255];
			
			tvb_memcpy(tvb, &donnee8, 14, c_increment8);prive->link11_state.subtype =(int)(donnee8&0xff);
			tvb_memcpy(tvb, &donnee8, 15, c_increment8);prive->link11_state.stn = (int)(donnee8&0xff);
				

			col_add_fstr(pinfo->cinfo, COL_INFO, "Link 11 - PU:%s - %s - %s Len=%02d",
				traduire_numero_piste((long)(donnee8&0xff), info),
				val_to_str(prive->link11_state.subtype, SimpleLibelleSubtypeL11 , (const gchar *)"Unknown:0x%02x"),
				simple->encoding==ENC_LITTLE_ENDIAN?"LE":"BE", t);
		}
	}

	if (tree)
	{ /* we are being asked for details */
		proto_item *simple_item        = NULL;
		proto_item *simple_sub_item[e_nombre_champs] ;
		proto_tree *simple_tree[e_nombre_champs] ; 
		proto_tree *simple_network_tree = NULL; 
		guint32 offset = 0;
		int i = 0;
		int taille_paquet = 0;



		simple_item                   = proto_tree_add_item(tree, proto_simple, tvb, 0, -1, ENC_NA);


		for (i=0;i<e_nombre_champs;i++)
		{
		    simple_tree[i]  = proto_item_add_subtree(simple_item, *simple->ett[i]);
		}

		simple_sub_item [e_network]    = proto_tree_add_item( simple_tree[e_simple], simple->network.hf.id , tvb, offset, -1, FALSE );
		simple_tree[e_network]         = proto_item_add_subtree(simple_sub_item[e_network], (const)*simple->ett[e_network]);


		//header
		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		proto_tree_add_uint(simple_tree[e_network], simple->network.hf.synch_byte_1, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;
		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		proto_tree_add_uint(simple_tree[e_network], simple->network.hf.synch_byte_2, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee16, offset, c_increment16);
		proto_tree_add_uint(simple_tree[e_network], simple->network.hf.length, tvb, offset, c_increment16, donnee16);
		offset+=c_increment16;

		tvb_memcpy(tvb, &donnee16, offset, c_increment16);
		proto_tree_add_uint(simple_tree[e_network], simple->network.hf.sequence, tvb, offset, c_increment16, donnee16);
		offset+=c_increment16;

		//packet
		simple_sub_item [e_packet]    = proto_tree_add_item( simple_tree[e_simple], simple->packet.hf.id , tvb, offset, -1, FALSE );
		simple_tree[e_packet]         = proto_item_add_subtree(simple_sub_item[e_packet], (const)simple->packet.ett.id);

		proto_tree_add_item(simple_tree[e_packet], simple->packet.hf.source_node, tvb, offset, 1, simple->encoding);
	    tvb_memcpy(tvb, &donnee8, offset, 1);prive->link16_state.header.node =(int)(donnee8&0xff);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		proto_tree_add_uint(simple_tree[e_packet], simple->packet.hf.source_subnode, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		proto_tree_add_uint(simple_tree[e_packet], simple->packet.hf.destination_node, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		proto_tree_add_uint(simple_tree[e_packet], simple->packet.hf.destination_subnode, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		taille_paquet = (int)donnee8;
		proto_tree_add_uint(simple_tree[e_packet], simple->packet.hf.size, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee8, offset, c_increment8);
		proto_tree_add_uint(simple_tree[e_packet], simple->packet.hf.type, tvb, offset, c_increment8, donnee8);
		offset+=c_increment8;

		tvb_memcpy(tvb, &donnee16, offset, c_increment16);
		proto_tree_add_uint(simple_tree[e_packet], simple->packet.hf.transit_time, tvb, offset, c_increment16, donnee16);
		offset+=c_increment16;


		//data
		simple_sub_item [e_packet_data]    = proto_tree_add_item( simple_tree[e_packet], simple->packet_data.hf.id , tvb, offset, -1, FALSE );
		simple_tree[e_packet_data]         = proto_item_add_subtree(simple_sub_item[e_packet_data], (const)simple->packet_data.ett.id);

		switch( type )
		{
			
		case e_Link16_type:
			simple_sub_item [e_link16]    = proto_tree_add_item( simple_tree[e_packet_data], simple->link_16.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_link16]         = proto_item_add_subtree(simple_sub_item[e_link16], (const)*simple->ett[e_link16]);
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.subtype, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.rc_flag, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.net, tvb, offset, 1, simple->encoding);
			tvb_memcpy(tvb, &donnee8, offset, c_increment8);prive->link16_state.header.net = (int)(donnee8&0xff);
			offset += 1;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.slot_count_2, tvb, offset, 1, simple->encoding);
			offset += 1;
			tvb_memcpy(tvb, &donnee16, offset, c_increment16);
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.npg, tvb, offset, 2, simple->encoding);
			prive->link16_state.header.npg = (int)(donnee16&0xffff);
            offset += 2;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.slot_count_1, tvb, offset, 2, simple->encoding);
			offset += 2;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.stn, tvb, offset, 2, simple->encoding);
			tvb_memcpy(tvb, &donnee16, offset, c_increment16);prive->link16_state.header.stn = (int)(donnee16&0xffff);
			proto_tree_add_text(simple_tree[e_link16], tvb, offset, 2,"STN=%s",traduire_numero_piste((long)(donnee16&0xffff),(char *)stn_s));
			offset += 2;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.word_count, tvb, offset, 2, simple->encoding);
			offset += 2;
			proto_tree_add_item(simple_tree[e_link16], simple->link_16.hf.loopback_id, tvb, offset, 2, simple->encoding);
			offset += 2;
			        
			{
				tvbuff_t *next_tvb;
				next_tvb = tvb_new_subset_remaining(tvb, offset);		
                if (l16_handle)
					call_dissector_with_data( l16_handle, next_tvb, pinfo, simple_tree[e_link16], &prive->link16_state);
			}
			break;
		case e_Link11_type:
			simple_sub_item [e_link11]    = proto_tree_add_item( simple_tree[e_packet_data], simple->link_11.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_link11]         = proto_item_add_subtree(simple_sub_item[e_link11], (const)*simple->ett[e_link11]);
			proto_tree_add_item(simple_tree[e_link11], simple->link_11.hf.subtype, tvb, offset, 1, simple->encoding);
			tvb_memcpy(tvb, &donnee8, offset, c_increment8);  prive->link11_state.subtype = donnee8;
			offset += 1;
			proto_tree_add_item(simple_tree[e_link11], simple->link_11.hf.pu, tvb, offset, 1, simple->encoding);
			tvb_memcpy(tvb, &donnee8, offset, c_increment8);  prive->link11_state.stn = donnee8;
			proto_tree_add_text(simple_tree[e_link11], tvb, offset, 1,"PU=%s",traduire_numero_piste((long)(donnee8&0xff),(char *)stn_s));
			offset += 1;
			tvb_memcpy(tvb, &donnee8, offset, c_increment8); 
			proto_tree_add_item(simple_tree[e_link11], simple->link_11.hf.word_count, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_link11], simple->link_11.hf.sequence_number, tvb, offset, 1, simple->encoding);
			offset += 1;
			prive->link11_state.taille = ((int)(donnee8&0xff))*2;
			{
				tvbuff_t *next_tvb;
				next_tvb = tvb_new_subset_remaining(tvb, offset);		
                if (link11_handle)
					call_dissector_with_data( link11_handle, next_tvb, pinfo, simple_tree[e_link11], &prive->link11_state);
			}
			break;
		case e_Link11B_type:
			simple_sub_item [e_link11b]    = proto_tree_add_item( simple_tree[e_packet_data], simple->link_11b.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_link11b]         = proto_item_add_subtree(simple_sub_item[e_link11b], (const)*simple->ett[e_link11b]);
			proto_tree_add_item(simple_tree[e_link11b], simple->link_11b.hf.destination_pu, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_link11b], simple->link_11b.hf.source_pu, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_link11b], simple->link_11b.hf.word_count, tvb, offset, 1, simple->encoding);
			offset += 1;
			prive->link11_state.taille = (taille_paquet - 4)*2;
			{
				tvbuff_t *next_tvb;
				next_tvb = tvb_new_subset_remaining(tvb, offset);		
                if (link11_handle)
					call_dissector_with_data( link11_handle, next_tvb, pinfo, simple_tree[e_link16], &prive->link11_state);
			}
			break;
		case e_DIS_type:
			simple_sub_item [e_dis]    = proto_tree_add_item( simple_tree[e_packet_data], simple->dis.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_dis]         = proto_item_add_subtree(simple_sub_item[e_dis], (const)*simple->ett[e_dis]);
			proto_tree_add_item(simple_tree[e_dis], simple->dis.hf.segment_number , tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_dis], simple->dis.hf.number_of_segments , tvb, offset, 1, simple->encoding);
			offset += 1;
			        
			{
				tvbuff_t *next_tvb;
				next_tvb = tvb_new_subset_remaining(tvb, offset);	
                if (dis_handle)
					call_dissector_with_data( dis_handle, next_tvb, pinfo, simple_tree[e_dis],(void *)&prive->dis_state);
			}
		break;
		case e_StatusConfiguration_type:

			simple_sub_item [e_node_status]    = proto_tree_add_item( simple_tree[e_packet_data], simple->node_status.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_node_status]         = proto_item_add_subtree(simple_sub_item[e_node_status], (const)*simple->ett[e_node_status]);
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.subtype, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.number_of_words, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.name, tvb, offset, 10, simple->encoding);
			offset += 10;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.hours, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.id, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.secondes, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.minutes, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.security_level, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.node_entry, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.relay_hope_node, tvb, offset, 15, simple->encoding);
			offset += 15;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.DX, tvb, offset, 1, simple->encoding);
			offset += 1 +1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.DX_file_id, tvb, offset, 8, simple->encoding);
			offset += 8 + 2;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.mids_jtids_terminal_type, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.mids_jtids_role, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.mids_jtids_synch_status, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.mids_jtids_terminal_host_status, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.mids_jtids_stn, tvb, offset, 1, simple->encoding);
			offset += 2 + 2;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.link11_dts_type, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.link11_role, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.link11_pu, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_node_status], simple->node_status.hf.link11_dts_host_status, tvb, offset, 1, simple->encoding);
			offset += 1;
			break;
		case e_RTT_type:
			simple_sub_item [e_rtt]    = proto_tree_add_item( simple_tree[e_packet_data], simple->rtt.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_rtt]         = proto_item_add_subtree(simple_sub_item[e_rtt], (const)*simple->ett[e_rtt]);
			proto_tree_add_item(simple_tree[e_rtt], simple->rtt.hf.node, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_rtt], simple->rtt.hf.port, tvb, offset, 1, simple->encoding);
			offset += 1;
			proto_tree_add_item(simple_tree[e_rtt], simple->rtt.hf.time_stamp, tvb, offset, 4, simple->encoding);
			offset += 4;
			break;
		case e_TimeSynchronisation_type:
			simple_sub_item [e_time_synchro]    = proto_tree_add_item( simple_tree[e_packet_data], simple->time_synchro.hf.id , tvb, offset, -1, FALSE );
			simple_tree[e_time_synchro]         = proto_item_add_subtree(simple_sub_item[e_time_synchro], (const)*simple->ett[e_time_synchro]);
			proto_tree_add_item(simple_tree[e_time_synchro], simple->time_synchro.hf.node, tvb, offset, 1, simple->encoding);
			offset += 2;
			proto_tree_add_item(simple_tree[e_time_synchro], simple->time_synchro.hf.utc, tvb, offset, 4, simple->encoding);
			offset += 4;
			proto_tree_add_item(simple_tree[e_time_synchro], simple->time_synchro.hf.exercise_offset, tvb, offset, 4, simple->encoding);
			offset += 4;
			break;

		default:
			{
				 char unknown[20];
				 sprintf(unknown,"Unknown %d", type);
			     proto_item_append_text(simple_tree[e_packet_data], " %s", val_to_str_const(type, SimpleLibelleSimpleType, unknown));
			}
			break;
		}
		//header checksum
		offset = length - 2;
		tvb_memcpy(tvb, &donnee16, offset, c_increment16);

		proto_tree_add_uint(simple_tree[e_network], simple->network.hf.checksum, tvb, offset, c_increment16, donnee16);

		
	}
	return tvb_captured_length(tvb);

}




