/* packet-L11.c
 * 
 * Routines for Link 11 message dissection (STANAG 5511)
 * Copyright 17/09/2015   Pierre-Henri BOURDELLE <pierre-henri.bourdelle@hotmail.fr>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>



#include <string.h>
# include "packet-L11.h"

#define PROTO_TAG_L11	"L11 PHB"

/* Wireshark ID of the L11 protocol */
static int proto_l11 = -1;



/* These are the handles of our subdissectors */
static dissector_handle_t data_handle=NULL;

static dissector_handle_t link11_handle;
gint dissect_l11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);

static int global_link11_port = 999;

static const value_string packettypenames[] = {
	{ 0, "M0" },
	{ 1, "M1" },
	{ 2, "M2" },
	{ 3, "M3" },
	{ 4, "M4" },
	{ 5, "M5" },
	{ 6, "M6" },
	{ 7, "M7" },
	{ 8, "M8" },
	{ 9, "M9" },
	{ 10, "M10" },
	{ 11, "M11" },
	{ 12, "M12" },
	{ 13, "M13" },
	{ 14, "M14" },
	{ 15, "M15" },
	{ 0, NULL }
};	


/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_l11()
*/
//static int hf_link11_pdu = -1;
/** Kts attempt at defining the protocol */
static gint hf_l11 = -1;
static gint hf_rp = -1;
static gint hf_type = -1;
static gint hf_spi = -1;
static gint hf_sim = -1;


/* These are the ids of the subtrees that we may be creating */
static gint ett_l11 = -1;
static gint ett_link11_header = -1;
static gint ett_link11_length = -1;
static gint ett_link11_type = -1;
static gint ett_link11_text = -1;


void proto_reg_handoff_l11(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {
		link11_handle = create_dissector_handle(dissect_l11, proto_l11);
		dissector_add_uint("tcp.port", global_link11_port, link11_handle);
		dissector_add_uint("udp.port", global_link11_port, link11_handle);
	}

}
static hf_register_info hf[] = {
	{ &hf_l11,
	{ "Data", "l11.data", FT_NONE, BASE_NONE, NULL, 0x0,
	"L11 PDU", HFILL }},
	{ &hf_type,
	{ "Type", "l11.type", FT_UINT8, BASE_DEC, VALS(packettypenames), 0xf,
	"Package Type", HFILL }},
	{ &hf_rp,
	{ "R/P", "l11.rp", FT_UINT8, BASE_DEC, NULL, 0x10,
	"Reference Position", HFILL }},
	{ &hf_spi,
	{ "SPI", "l11.spi", FT_UINT8, BASE_DEC, NULL, 0x20,
	"Special Processing Indicator", HFILL }},
	{ &hf_sim,
	{ "SIM", "l11.sim", FT_UINT8, BASE_DEC, NULL, 0x40,
	"Simulation  Indicator", HFILL }}
};

static int* const l11_M_fields[][15] = {
	{&hf_type,//M0
	NULL
	},
	{&hf_type,//M1
	&hf_rp,
	&hf_spi,
	&hf_sim,
	NULL
	},
	{&hf_type,//M2
	NULL
	},
	{&hf_type,//M3
	NULL
	},
	{&hf_type,//M4
	NULL
	},
	{&hf_type,//M5
	NULL
	},
	{&hf_type,//M6
	NULL
	},
	{&hf_type,//M7
	NULL
	},
	{&hf_type,//M8
	NULL
	},
	{&hf_type,//M9
	NULL
	},
	{&hf_type,//M10
	NULL
	},
	{&hf_type,//M11
	NULL
	},
	{&hf_type,//M12
	NULL
	},
	{&hf_type,//M13
	NULL
	},
	{&hf_type,//M14

	NULL
	},
	{&hf_type,//M15

	NULL
	},
};
void proto_register_l11 (void)
{
	/* A header field is something you can search/filter on.
	* 
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/



	static gint *ett[] = {
		&ett_l11,
	};

	proto_l11 = proto_register_protocol ("PHB SIMPLE Link11 Protocol", "PHB SIMPLE Link11", "simple_l11");

	proto_register_field_array (proto_l11, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	register_dissector("l11", dissect_l11, proto_l11);

}
	
static gint dissect_l11(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	proto_item *link11_item = NULL;
	proto_item *link11_sub_item = NULL;
	proto_tree *link11_tree = NULL;
	proto_tree *link11_header_tree = NULL; 
	guint16 type = 0;
	L11State *etat = (L11State *)data;
	int taille = etat->taille;

	if (!etat)
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_L11);
	else
	{
		char str[11];
		sprintf(str, "SIMPLE %s",PROTO_TAG_L11);
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_L11);
	};

	col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Info Type:[%s]",
		pinfo->srcport, pinfo->destport, 
		val_to_str(type, packettypenames, "Unknown Type:0x%02x"));

	if (tree&&taille) { /* we are being asked for details */
		guint32 offset = 0;
		

		link11_item = proto_tree_add_item(tree, proto_l11, tvb, 0, -1, FALSE);
		link11_tree = proto_item_add_subtree(link11_item, ett_l11);
		link11_header_tree = proto_item_add_subtree(link11_item, ett_l11);

		link11_sub_item = proto_tree_add_item( link11_tree, hf_l11, tvb, offset, -1, FALSE );
		link11_header_tree = proto_item_add_subtree(link11_sub_item, ett_l11);

		while (taille)
		{
			int numero = 0;
			guint8  donnee8   = 0;

			tvb_memcpy(tvb, &donnee8, offset, 1);
            numero = (int)(donnee8&0xf);
			proto_tree_add_bitmask_text(link11_tree, tvb, offset, 1, "Message", NULL, ett_l11, l11_M_fields[numero], ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
			offset+=8;taille -= 8;
		}
	}

	return tvb_captured_length(tvb);

}	
