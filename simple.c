#include "simple.h"
typedef const gchar T_Texte;

value_string SimpleLibelleSubtypeL11[] =
{
	0,(T_Texte *)"intermediate",
	1,"Interrogate Message",
	2,"Start Code",
	3,"Picket Stop Code",
	4,"Control Stop Code",
	0,NULL
};
value_string SimpleLibelleNode[]= 
{
	    0, "Illegal",
		129,"All Nodes Broadcast",
		161,"Node Multicast Group 1 -NG1-",
		162,"Node Multicast Group 2 -NG2-",
		163,"Node Multicast Group 3 -NG3-",
		164,"Node Multicast Group 4 -NG4-",
		165,"Node Multicast Group 5 -NG5-",
		166,"Node Multicast Group 6 -NG6-",
		167,"Node Multicast Group 7 -NG7-",
		168,"Node Multicast Group 8 -NG8-",
		169,"Next  Adjacent  Node on this circuit",
		0,NULL
};

value_string SimpleLibelleSubNode[] = 
{
	0,"Illegal", 
		1 ,"RTT Messages", 
		2 ,"Terminal-Host Interface", 
		3 ,"Undefined", 
		4 ,"File & Mail Transfers", 
		5 ,"Open", 
		6 ,"Status & Control Messages", 
		7 ,"Time Synchronisation Process ", 
		202 ,"Scenario Script Data",
		203 ,"IJMS Data",
		204 ,"LINK-4 Data",
		205 ,"LINK-11 Data",
		206 ,"LINK-16 Data",
		207 ,"LINK-22 Data",
		208 ,"DIS/PDU Data",
		209 ,"Voice Group A",
		210 ,"Voice Group B",
		211 ,"LINK-11B Data",
		251 ,"illegal 251",
		252 ,"illegal 252",
		253 ,"illegal 253",
		254 ,"illegal 254",
		255 ,"illegal 255",
		0,NULL
};


value_string SimpleLibelleL16SubType[] = 
{
	0,"Uncoded Free Text", 
	1 ,"Coded Free Text", 
	2 ,"Link 16 Fixed Format", 
	0,NULL
};
value_string SimpleLibelleSecurityLevel[] = 
{
	0,"Unclassified", 
	1 ,"NATO Unclassified", 
	2 ,"Confidential", 
	3 ,"NATO Confidential", 
	4 ,"Secret", 
	5 ,"NATO Secret", 
	6 ,"National Only", 
	0,NULL
};
value_string SimpleLibelle_l16_terminal_type[] = 
{
	0,"Unclassified", 
	1 ,"US Navy Air (JTIDS)", 
	2 ,"US Navy Ship (JTIDS)", 
	3 ,"US F-15 (JTIDS)", 
	4 ,"US F/A-18 (MIDS)", 
	5 ,"US Army Class 2M (JTIDS)", 
	6 ,"US MCE (JTIDS)", 
	7 ,"E-3 (JTIDS)", 
	8 ,"UK Tornado F3 (JTIDS)", 
	9 ,"UK UKADGE (JTIDS)", 
	10 ,"Low Volume Terminal - Generic (MIDS)", 
	11 ,"Low Volume Terminal - Platform Type A", 
	12 ,"Low Volume Terminal - Platform Type B", 
	13 ,"Low Volume Terminal - Platform Type C", 
	14 ,"Low Volume Terminal - Platform Type D", 
	15 ,"Low Volume Terminal - Platform Type E", 
	16 ,"Low Volume Terminal - Platform Type F", 
	17 ,"Low Volume Terminal - Platform Type G", 
	18 ,"Low Volume Terminal 2, US Army (MIDS)", 
	19 ,"Low Volume Terminal MIDS on Ship (MOS)", 
	20 ,"US Fighter Data Link (FDL) (MIDS)", 
	21 ,"AN/URC-138", 
	22 ,"Low Volume Terminal Platform Type H", 
	23 ,"Low Volume Terminal Platform Type I", 
	0,NULL
};
value_string SimpleLibelle_l16_terminal_host_status[] = 
{
	0,"Inactive", 
	1 ,"Active", 
	0,NULL
};
value_string SimpleLibelle_l16_sync_status[] = 
{
	0 ,"None", 
	1 ,"Net Entry in Progress", 
	2 ,"Confidential", 
	3 ,"Coarse Sync", 
	4 ,"Fine Sync", 
	5 ,"NATO Secret", 
	0 ,NULL
};
value_string SimpleLibelle_l16_role[] = 
{
	0,"None", 
	1 ,"SIMPLE Host (SH)", 
	2 ,"SIMPLE Terminal Emulator (STE)", 
	3 ,"SIMPLE Network Monitor (SNM)", 
	4 ,"SIMPLE Virtual Host (SVH)", 
	5 ,"SIMPLE Virtual Terminal (SVT)",  
	0,NULL
};
value_string SimpleLibelle_l11_role[] = 
{
	0,"None", 
	1 ,"SIMPLE DTS EMULATOR (SDE) Picket", 
	2 ,"SDE Net Control Station (NCS)", 
	3 ,"SIMPLE Participating Unit (PU) Emulator (SPE)", 
	0,NULL
};
value_string SimpleLibelle_l11_dts_type[] = 
{
	0,"None", 
	1 ,"MIL-STD-1397 parallel", 
	2 ,"MIL-STD-188-203-1A serial", 
	0,NULL
};
value_string SimpleLibelle_l11_status[] = 
{
	0,"Inactive", 
	1 ,"Active",  
	0,NULL
};

value_string SimpleLibelleSimpleSecurityLevel[] = 
{
	0,"Unclassified", 
	1 ,"NATO", 
	2 ,"Confidential", 
	3 ,"NATO", 
	4 ,"Secret", 
	5 ,"NATO Secret", 
	6 ,"National", 
	7 ,"National", 
	8 ,"National", 
	9 ,"National", 
	10 ,"National", 
	11 ,"National", 
	12 ,"National", 
	13 ,"National", 
	14 ,"National", 
	15 ,"National", 
	16 ,"National", 
	17 ,"National", 
	18 ,"National", 
	19 ,"National", 
	20 ,"National", 
	21 ,"National", 
	22 ,"National", 
	23 ,"National", 
	24 ,"National", 
	25 ,"National", 
	0,NULL
};


value_string SimpleLibelleSimpleType[] = 
{
	0,"Illegal", 
	1 ,"Link 16", 
	2 ,"Link 11", 
	3 ,"Link 4", 
	4 ,"Link 22", 
	5 ,"Interim JTIDS Message Standard (IJMS)", 
	6 ,"USA Messages 6", 
	7 ,"USA Messages 7", 
	8 ,"Variable Message Format (VMF)", 
	9 ,"TIM/TOM Data", 
	10 ,"MSTM Data", 
	12 ,"TADIL PDU", 
	13 ,"MIDS/JTIDS Voice", 
	20 ,"Link 11B", 
	30 ,"SIF Event Data 30", 
	31 ,"SIF Event Data 31", 
	32 ,"DIS Protocol Data Unit (PDU)", 
	33 ,"TDSIU Events", 
	34 ,"JITC SS Events", 
	61 ,"Status/Configuration", 
	62 ,"E-mail/File Transfer Protocol (FTP)", 
	63 ,"Round Trip Timing (RTT)", 
	64 ,"Gateway Voice", 
	65 ,"Time Synchronisation", 
	66 ,"TSA Status", 
	100 ,"National Message", 
	101 ,"USA Messages", 
	0,NULL
};

