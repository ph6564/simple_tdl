
/* packet-l16.c
 * Routines for Link 16 in SIMPLE messages  dissection (MIL-STD-6016)
 * initialised by William Robertson <aliask@gmail.com>
 * and Peter Ross <peter.ross@dsto.defence.gov.au>
 * Copyright 17/09/2015   Pierre-Henri BOURDELLE <pierre-henri.bourdelle@hotmail.fr>
 * 
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-L16.h"

void proto_register_L16(void);

/* Elmasry, G., (2012), Tactical Wireless Communications and Networks: Design Concepts and Challenges, Wiley, ISBN 9781119951766. */
enum {
    WORDFORMAT_INITIAL = 0,
    WORDFORMAT_CONTINUATION,
    WORDFORMAT_EXTENSION
};

static const value_string WordFormat_Strings[] = {
    { WORDFORMAT_INITIAL, "Initial Word" },
    { WORDFORMAT_CONTINUATION, "Continuation Word" },
    { WORDFORMAT_EXTENSION, "Extension Word" },
    { 0, NULL },
};

/* Viasat, Inc., (2012), Link 16 Network Participant Group and Message Card, accessed from <http://www.viasat.com/files/assets/assets/Link16_NPG_Message_Card_100112a.pdf> on 15 April 2013. */
static const value_string Link16_Label_Strings[] = {
    { 0, "Network Management" },
    { 1, "Network Management" },
    { 2, "Precise Participant Location and Identification" },
    { 3, "Surveillance" },
    { 5, "Anti-submarine Warfare" },
    { 6, "Intelligence" },
    { 7, "Information Management" },
    { 8, "Information Management" },
    { 9, "Weapons Coordination and Management" },
    { 10, "Weapons Coordination and Management" },
    { 11, "Weapons Coordination and Management" },
    { 12, "Control" },
    { 13, "Platform and System Status" },
    { 14, "Electronic Warfare" },
    { 15, "Threat Warning" },
    { 16, "Imagery" },
    { 17, "Weather" },
    { 28, "National Use" },
    { 29, "National Use" },
    { 30, "National Use" },
    { 31, "Miscellaneous" },
    { 0, NULL },
};

/* Viasat, Inc., (2012), Link 16 Network Participant Group and Message Card, accessed from <http://www.viasat.com/files/assets/assets/Link16_NPG_Message_Card_100112a.pdf> on 15 April 2013. */
#define MKPAIR(a, b) (((b) << 5) | (a))
static const value_string Link16_Message_Strings[] = {
    { MKPAIR(0, 0), "Initial Entry" },
    { MKPAIR(0, 1), "Test" },
    { MKPAIR(0, 2), "Network Time Update" },
    { MKPAIR(0, 3), "Time Slot Assignment" },
    { MKPAIR(0, 4), "Radio Relay Control" },
    { MKPAIR(0, 5), "Repromulgation Relay" },
    { MKPAIR(0, 6), "Communication Control" },
    { MKPAIR(0, 7), "Time Slot Reallocation" },
    { MKPAIR(1, 0), "Connectivity Interrogation" },
    { MKPAIR(1, 1), "Connectivity Status" },
    { MKPAIR(1, 2), "Route Establishment" },
    { MKPAIR(1, 3), "Acknowledgment" },
    { MKPAIR(1, 4), "Communication Status" },
    { MKPAIR(1, 5), "Net Control Initialization" },
    { MKPAIR(1, 6), "Needline Participation Group Assignment" },
    { MKPAIR(2, 0), "Indirect Interface Unit PPLI" },
    { MKPAIR(2, 2), "Air PPLI" },
    { MKPAIR(2, 3), "Surface PPLI" },
    { MKPAIR(2, 4), "Subsurface PPLI" },
    { MKPAIR(2, 5), "Land Point PPLI" },
    { MKPAIR(2, 6), "Land Track PPLI" },
    { MKPAIR(3, 0), "Reference Point" },
    { MKPAIR(3, 1), "Emergency Point" },
    { MKPAIR(3, 2), "Air Track" },
    { MKPAIR(3, 3), "Surface Track" },
    { MKPAIR(3, 4), "Subsurface Track" },
    { MKPAIR(3, 5), "Land Point or Track" },
    { MKPAIR(3, 6), "Space Track" },
    { MKPAIR(3, 7), "Electronic Warfare Product Information" },
    { MKPAIR(5, 4), "Acoustic Bearing and Range" },
    { MKPAIR(6, 0), "Amplification" },
    { MKPAIR(7, 0), "Track Management" },
    { MKPAIR(7, 1), "Data Update Request" },
    { MKPAIR(7, 2), "Correlation" },
    { MKPAIR(7, 3), "Pointer" },
    { MKPAIR(7, 4), "Track Identifier" },
    { MKPAIR(7, 5), "IFF/SIF Management" },
    { MKPAIR(7, 6), "Filter Management" },
    { MKPAIR(7, 7), "Association" },
    { MKPAIR(8, 0), "Unit Designator" },
    { MKPAIR(8, 1), "Mission Correlator Change" },
    { MKPAIR(9, 0), "Command" },
    { MKPAIR(10, 2), "Engagement Status" },
    { MKPAIR(10, 3), "Handover" },
    { MKPAIR(10, 5), "Controlling Unit Report" },
    { MKPAIR(10, 6), "Pairing" },
    { MKPAIR(11, 0), "From the Weapon" },
    { MKPAIR(11, 1), "To the Weapon" },
    { MKPAIR(11, 2), "Weapon Coordination" },
    { MKPAIR(12, 0), "Mission Assignment" },
    { MKPAIR(12, 1), "Vector" },
    { MKPAIR(12, 2), "Precision Aircraft Direction" },
    { MKPAIR(12, 3), "Flight Path" },
    { MKPAIR(12, 4), "Controlling Unit Change" },
    { MKPAIR(12, 5), "Target/Track Correlation" },
    { MKPAIR(12, 6), "Target Sorting" },
    { MKPAIR(12, 7), "Target Bearing" },
    { MKPAIR(13, 0), "Airfield Status" },
    { MKPAIR(13, 2), "Air Platform and System Status" },
    { MKPAIR(13, 3), "Surface Platform and System Status" },
    { MKPAIR(13, 4), "Subsurface Platform and System Status" },
    { MKPAIR(13, 5), "Land Platform and System Status" },
    { MKPAIR(14, 0), "Parametric Information" },
    { MKPAIR(14, 2), "Electronic Warfare Control / Coordination" },
    { MKPAIR(15, 0), "Threat Warning" },
    { MKPAIR(16, 0), "Imagery" },
    { MKPAIR(17, 0), "Weather Over target" },
    { MKPAIR(28, 0), "U.S. National 1 (Army)" },
    { MKPAIR(28, 1), "U.S. National 2 (Navy)" },
    { MKPAIR(28, 2), "U.S. National 3 (Air Force)" },
    { MKPAIR(28, 3), "U.S. National 4 (Marine Corps)" },
    { MKPAIR(28, 4), "French National 1" },
    { MKPAIR(28, 5), "French National 2" },
    { MKPAIR(28, 6), "U.S. National 5 (NSA)" },
    { MKPAIR(28, 7), "UK National" },
    { MKPAIR(31, 0), "Over-the-Air Rekeying Management" },
    { MKPAIR(31, 1), "Over-the-Air Rekeying" },
    { MKPAIR(31, 7), "No Statement" },
    { 0, NULL },
};

/* Viasat, Inc., (2012), Link 16 Network Participant Group and Message Card, accessed from <http://www.viasat.com/files/assets/assets/Link16_NPG_Message_Card_100112a.pdf> on 15 April 2013. */
const value_string Link16_NPG_Strings[] = {
    { 1, "Initial Entry" },
    { 2, "RTT-A" },
    { 3, "RTT-B" },
    { 4, "Network Management" },
    { 5, "PPLI and Status" },
    { 6, "PPLI and Status" },
    { 7, "Surveillance" },
    { 8, "Mission Management/Weapons Coordination" },
    { 9, "Control" },
    { 11, "Image Transfer" },
    { 12, "Voice A" },
    { 13, "Voice B" },
    { 18, "Network Enabled Weapons" },
    { 19, "Fighter-to-Fighter A" },
    { 20, "Fighter-to-Fighter B" },
    { 21, "Engagement Coordination" },
    { 27, "Joint Net PPLI" },
    { 28, "Distributed Network Management" },
    { 0, NULL },
};

static int proto_L16 = -1;

static gint hf_L16_wordformat = -1;
static gint hf_L16_label = -1;
static gint hf_L16_sublabel = -1;
static gint hf_L16_mli = -1;
static gint hf_L16_contlabel = -1;

static gint ett_L16 = -1;

static  int* const l16_initial_word_fields[] = {
    &hf_L16_wordformat,
    &hf_L16_label,
    &hf_L16_sublabel,
    &hf_L16_mli,
    NULL
};

static  int* const  l16_continuation_word_fields[] = {
    &hf_L16_wordformat,
    &hf_L16_contlabel,
    NULL
};

static  int * const  l16_extension_or_other_word_fields[] = {
    &hf_L16_wordformat,
    NULL
};

static  int* const *  l16_fields[4] = {
    l16_initial_word_fields,
    l16_continuation_word_fields,
    l16_extension_or_other_word_fields,
    l16_extension_or_other_word_fields
};
		 
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


static int dissect_L16(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    Link16State *state = (Link16State *)data;
    proto_item *l16_item = NULL;
    proto_tree *l16_tree = NULL;
    guint16 cache;
    guint8 wordformat, contlabel;
	static char stn_s[6];

    if (!state)
        REPORT_DISSECTOR_BUG("Link 16 Simple dissector state missing");

	traduire_numero_piste(state->header.stn, stn_s);
    cache = tvb_get_letohs(tvb, 0);
    wordformat = cache & 0x3;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIMPLE L16");

    if (tree) {
        l16_item = proto_tree_add_item(tree, proto_L16, tvb, 0, -1, ENC_NA);
        l16_tree = proto_item_add_subtree(l16_item, ett_L16);
        proto_tree_add_bitmask_text(l16_tree, tvb, 0, 2, "Header", NULL, ett_L16, l16_fields[wordformat], ENC_LITTLE_ENDIAN, BMT_NO_APPEND);
    }

    /* Elmasry, G., (2012), Tactical Wireless Communications and Networks: Design Concepts and Challenges, Wiley, ISBN 9781119951766. */
    switch (wordformat) {
    case WORDFORMAT_INITIAL:
        state->label     = (cache >> 2) & 0x1F;
        state->sublabel  = (cache >> 7) & 0x7;
        state->extension = 0;
		col_append_fstr(pinfo->cinfo, COL_INFO, " J%d.%dI %d %s", state->label, state->sublabel, state->header.npg, stn_s);
		proto_item_append_text(l16_item, " J%d.%dI ", state->label, state->sublabel, state->sublabel);
        break;
    case WORDFORMAT_EXTENSION:
        col_append_fstr(pinfo->cinfo, COL_INFO, " J%d.%dE%d %s %d" , state->label, state->sublabel, state->extension, state->sublabel,stn_s, state->header.npg);

        proto_item_append_text(l16_item, " J%d.%dE%d %s %d", state->label, state->sublabel, state->extension, state->sublabel,stn_s, state->header.npg);
        state->extension++;
        break;
    case WORDFORMAT_CONTINUATION:
        contlabel = (cache >> 2) & 0x1F;
        col_append_fstr(pinfo->cinfo, COL_INFO, " J%d.%dC%d %s %d", state->label, state->sublabel, contlabel, state->sublabel,stn_s, state->header.npg);

        proto_item_append_text(l16_item, " J%d.%dC%d %s %d", state->label, state->sublabel, contlabel, state->sublabel,stn_s, state->header.npg);
    }

    proto_item_append_text(l16_item, " %s", val_to_str_const(MKPAIR(state->label, state->sublabel), Link16_Message_Strings, "Unknown"));

    return tvb_captured_length(tvb);

}


void proto_register_L16(void)
{
    static hf_register_info hf[] = {
        { &hf_L16_wordformat,
          { "Word Format", "l16.wordformat", FT_UINT16, BASE_DEC, VALS(WordFormat_Strings), 0x3,
            NULL, HFILL }},
        { &hf_L16_label,
          { "Label", "l16.label", FT_UINT16, BASE_DEC, VALS(Link16_Label_Strings), 0x7C,
            NULL, HFILL }},
        { &hf_L16_sublabel,
          { "Sublabel", "l16.sublabel", FT_UINT16, BASE_DEC, NULL, 0x380,
            NULL, HFILL }},
        { &hf_L16_mli,
          { "Message Length Indicator", "l16.mli", FT_UINT16, BASE_DEC, NULL, 0x1C00,
            NULL, HFILL }},
        { &hf_L16_contlabel,
          { "Continuation Word Label", "l16.contlabel", FT_UINT16, BASE_DEC, NULL, 0x7C,
            NULL, HFILL }}
    };
    static gint *ett[] = {
        &ett_L16,
    };

    proto_L16 = proto_register_protocol("SIMPLE Link 16", "SIMPLE Link16", "simple_l16");
    proto_register_field_array(proto_L16, hf, array_length (hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("phb_l16", dissect_L16, proto_L16);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
