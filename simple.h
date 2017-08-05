#ifndef SIMPLE 
#define SIMPLE


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <stdio.h>
#include <epan/value_string.h>


#define C_LONGUEUR_DONNEE_L11_SIMPLE	        4
#define C_LONGUEUR_ENTETE_SIMPLE_L16	        14
#define C_LONGUEUR_ENTETE_L16_SENIT8_RECEPTION	26
#define C_LONGUEUR_ENTETE_L16_SENIT8_EMISSION	30

#define C_LONGUEUR_CRC_SIMPLE			2
#define C_LONGUEUR_MOT_J_SIMPLE			10

#define WORD_S unsigned short int
#define DWORD_S unsigned int
#define BYTE_S  unsigned char
#define LONGLONG_S  unsigned __int8

#define FRONTIERE_OCTET __declspec(align(1))
#define FRONTIERE_MOT   __declspec(align(2))


//typedef struct ST_SimpleLibelleChamp
//{
//	unsigned int valeur;
//	char *libelle;
//} T_SimpleLibelleChamp;

extern value_string SimpleLibelleNode[];
extern value_string SimpleLibelleSubNode[];

typedef struct ST_SimpleNetworkHeader 
{
	BYTE_S sync1;  //49H
	BYTE_S sync2;  //36H
	WORD_S longueur;
	WORD_S numero;
} T_SimpleNetworkHeader;

typedef struct ST_SimplePacketHeader 
{
	BYTE_S source_node;
	BYTE_S source_subnode;
	BYTE_S destination_node;
	BYTE_S destination_subnode;
	BYTE_S packet_size;
	BYTE_S packet_type;
	WORD_S transit_time;
} T_SimplePacketHeader;

#define C_TAILLE_MAX_MESSAGE_SIMPLE  10000
#define C_SIMPLE_MAX_NOMBRE_MESSAGE_L11  100

typedef struct ST_SimpleMessage 
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	WORD_S mots[C_TAILLE_MAX_MESSAGE_SIMPLE];
} T_SimpleMessage;



typedef struct ST_SimpleEnteteL11 
{
	BYTE_S subtype;
	BYTE_S PU;
	BYTE_S word_count;
	BYTE_S sequence_number;
} T_SimpleEnteteL11;

typedef struct ST_SimpleL11 
{
	T_SimpleEnteteL11 entete;
} T_SimpleL11;
typedef struct ST_SimpleMessageL11 
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleEnteteL11 entete;
	WORD_S mots[C_TAILLE_MAX_MESSAGE_SIMPLE];
} T_SimpleMessageL11;




						
enum T_SimpleSubtypeL11 {	Intermediate, InterrogateMessage, StartCode,PicketStopCode, ControlStopCode};

typedef struct ST_SimpleRTT //Packet type 63
{
	BYTE_S originating_simple_id;
	BYTE_S port_id;
	DWORD_S time_stamp;
} T_SimpleRTT;
typedef struct ST_MessageSimpleRTT //Packet type 65
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleRTT data;
} T_MessageSimpleRTT;
typedef struct ST_SimpleTimeSynch //Packet type 65
{
	BYTE_S originating_simple_id;
	DWORD_S time;
	DWORD_S exercice_offset;
} T_SimpleTimeSynch;
typedef struct ST_MessageSimpleTimeSynch //Packet type 65
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleTimeSynch data;
} T_MessageSimpleTimeSynch;

typedef struct ST_SimpleStatusConfiguration //Packet type 61
{
	BYTE_S subtype;  //=1
	BYTE_S word_count;//4-60
	char simple_name[10];
	BYTE_S hour;
	BYTE_S simple_node_id;
	BYTE_S second;
	BYTE_S minute;
	BYTE_S security_level;
	BYTE_S node_entry_flag;
	BYTE_S relay_hope_node_1;
	BYTE_S relay_hope_node_2;
	BYTE_S relay_hope_node_3;
	BYTE_S relay_hope_node_4;
	BYTE_S relay_hope_node_5;
	BYTE_S relay_hope_node_6;
	BYTE_S relay_hope_node_7;
	BYTE_S relay_hope_node_8;
	BYTE_S relay_hope_node_9;
	BYTE_S relay_hope_node_10;
	BYTE_S relay_hope_node_11;
	BYTE_S relay_hope_node_12;
	BYTE_S relay_hope_node_13;
	BYTE_S relay_hope_node_14;
	BYTE_S relay_hope_node_15;
	BYTE_S relay_hope_node_16;
	BYTE_S espion;
	BYTE_S dx;
	char dx_file_id[8];
	WORD_S spare1;
	BYTE_S mids_jtids_type;// 0 - None  1 - SIMPLE Host (SH),  2 - SIMPLE Terminal Emulator (STE), 3 - SIMPLE Network Monitor (SNM), 4 - SIMPLE Virtual Host (SVH), 5 - SIMPLE Virtual Terminal (SVT)
	BYTE_S mids_jtids_role;//1 simple host
	BYTE_S mids_jtids_sync_status;//0 - None, 1 - Net Entry in Progress, 2 - Coarse Sync, 3 - Fine Sync
	BYTE_S jtids_terminal_host_status;//0 inactive
	WORD_S mids_jtids_stn;
	WORD_S Spare2;
	BYTE_S l11_dts_type;// 0 - none, 1 - MIL-STD-1397 parallel, 2 - MIL-STD-188-203-1A serial
	BYTE_S l11_role;// 0 - None, 1 - SIMPLE DTS EMULATOR (SDE) Picket, 2 - SDE Net Control Station (NCS), 3 - SIMPLE Participating Unit (PU) Emulator (SPE)
	BYTE_S l11_pu_number;// 
	BYTE_S dts_host_status;//0 - Inactive, 1 - Active
	WORD_S Spare3;
	WORD_S Spare4;
} T_SimpleStatusConfiguration;
typedef struct ST_MessageSimpleStatusConfiguration //Packet type 65
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleStatusConfiguration data;
} T_MessageSimpleTimeStatusConfiguration;
#define C_MAX_NOM_PU_STN 10
typedef struct ST_pu_stn_pairs
{
	WORD_S tn;
	char nom[10];
}T_pu_stn_pairs;
#define C_MAX_PU_STN 31

typedef struct ST_SimpleL11RFNetwork //Packet type 62 subtype 21
{
	BYTE_S subtype;//21
	BYTE_S number_of_words;//Number of 16-bit words in packet (2 + (6 x Number of PUs/STNs))
	BYTE_S simple_node_id;
	BYTE_S number_of_pu;
	T_pu_stn_pairs pu[C_MAX_PU_STN];
} T_SimpleL11RFNetwork;
typedef struct ST_MessageSimpleL11RFNetwork 
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleL11RFNetwork data;
} T_MessageSimpleL11RFNetwork;

typedef struct ST_SimpleL16RFNetwork //Packet type 62 subtype 22
{
	BYTE_S subtype;//22
	BYTE_S number_of_words;//Number of 16-bit words in packet (2 + (6 x Number of PUs/STNs))
	BYTE_S simple_node_id;
	BYTE_S number_of_iu;
	T_pu_stn_pairs iu[31];
} T_SimpleL16RFNetwork;
typedef struct ST_MessageSimpleL16RFNetwork 
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleL16RFNetwork data;
} T_MessageSimpleL16RFNetwork;

typedef struct ST_Port
{
	char name[10];
	char port;
	BYTE_S node_type;
	char channel[8];
	DWORD_S baud_rate;
	BYTE_S state;//1=On
	BYTE_S spare;
	BYTE_S node;
	BYTE_S subnode;
	DWORD_S sequence_in;
	DWORD_S sequence_out;
	DWORD_S drop_count;
} T_Port;

typedef struct ST_SimpleNodeCommunicationsConfigurationMessage //Packet type 62 subtype  23
{
	BYTE_S subtype;//23
	BYTE_S number_of_words;//Number of 16-bit words in packet (2 + (20 x Number of ports))
	BYTE_S simple_node_id;
	BYTE_S number_of_ports; //1-20
	T_Port port[20];
} T_SimpleNodeCommunicationsConfigurationMessage;
typedef struct ST_MessageSimpleNodeCommunicationsConfigurationMessage 
{
	T_SimpleNetworkHeader network_header;
	T_SimplePacketHeader packet_header;
	T_SimpleNodeCommunicationsConfigurationMessage data;
} T_MessageSimpleNodeCommunicationsConfigurationMessage;
#define C_SIMPLE_AllNodesBroadcast			129
#define C_SIMPLE_NextAdjacentNode			169

#define C_SIMPLE_RTTMessages				1
#define C_SIMPLE_TerminalHostInterface	    2
#define C_SIMPLE_Undefined_3				3
#define C_SIMPLE_FileAndMailTransfers		4
#define C_SIMPLE_Open						5
#define C_SIMPLE_StatusControlMessages		6
#define C_SIMPLE_TimeSynchronisationProcess 7
#define C_SIMPLE_ScenarioScriptData		202
#define C_SIMPLE_IJMS						203
#define C_SIMPLE_LINK_4						204
#define C_SIMPLE_LINK_11					205
#define C_SIMPLE_LINK_16					206
#define C_SIMPLE_LINK_22					207
#define C_SIMPLE_DIS						208
#define C_SIMPLE_VoiceGroupA				209
#define C_SIMPLE_VoiceGroupB				210
#define C_SIMPLE_PacketType_L11				2
#define C_SIMPLE_PacketType_L16				1
#define C_SIMPLE_PacketType_DIS				32
#define C_SIMPLE_PacketType_RTT				63
#define C_SIMPLE_PacketType_TimeSynchronisation				65
#define C_SIMPLE_PacketType_StatusConfiguration				61
#define C_SIMPLE_PacketType_NodeCommunicationsConfiguration				62

typedef FRONTIERE_OCTET struct ST_SimpleEntete16Senit8Reception
{
	DWORD_S  STN;
	WORD_S   NPG;
	WORD_S   LBID;
	WORD_S   Label;
	WORD_S   SubLabel;
	WORD_S   RC;
	WORD_S   LBSTAT;
	double HeureReception;
	WORD_S   NombreDeMots;
} T_SimpleEntete16Senit8Reception;


typedef FRONTIERE_OCTET struct ST_SimpleEnteteSimple
{
	BYTE_S  SubType;
	BYTE_S  RC;
	BYTE_S  Net;
	BYTE_S   SequentialCount2;
	WORD_S   NPG;
	WORD_S   SequentialCount1;
	WORD_S  STN;
	WORD_S   NombreDeMots;
	WORD_S   LBID;
} T_SimpleEnteteSimple;
#define C_EnteteSimpleL16_type_FormatFixe 2
#define C_EnteteSimpleL16_type_FormatLibre 1
#define C_EnteteSimpleL16_type_Voix 0
typedef  struct ST_SimpleEntete16Senit8Emission
{
    DWORD_S   STN;
	WORD_S    NPG;
	WORD_S    LBID;
	WORD_S    Label;
	WORD_S    SubLabel;
	WORD_S    Priorite;
	WORD_S    LimiteDAge;
	WORD_S    Repetition;
	WORD_S    IntervalleRepetition;	  
    double HeurePosition;
	WORD_S   NombreDeMots;
} T_SimpleEntete16Senit8Emission;

extern value_string SimpleLibelleSubtypeL11[] ;

extern value_string SimpleLibelleNode[];
extern value_string SimpleLibelleSubNode[];
extern value_string SimpleLibelleL16SubType[];
extern value_string SimpleLibelle_l11_status[]; 
extern value_string SimpleLibelle_l11_dts_type[]; 
extern value_string SimpleLibelle_l11_role[]; 
extern value_string SimpleLibelleSubtypeL11[]; 
extern value_string SimpleLibelle_l16_role[]; 
extern value_string SimpleLibelle_l16_sync_status[]; 
extern value_string SimpleLibelle_l16_terminal_host_status[]; 
extern value_string SimpleLibelle_l16_terminal_type[]; 
extern value_string SimpleLibelleSecurityLevel[]; 
extern value_string SimpleLibelleSimpleSecurityLevel[]; 
extern value_string SimpleLibelleSimpleType[]; 

extern char *libelle_subtype_L11[5];

enum e_SimpleType {	
	e_Link16_type = 1 ,
	e_Link11_type  ,
	e_Link4_type  ,
	e_Link22_type ,
	e_IJMS_type ,
	e_USAMessages6_type ,
	e_USAMessages7_type ,
	e_VMF_type  ,
	e_TIM_TOM_type  ,
	e_MSTM_type  ,
	e_TADIL_PDU_type  ,
	e_MIDS_JTIDS_Voice_type ,
	e_Link11B_type  ,
	e_DIS_type = 32  ,
	e_TDSIU_type  ,
	e_StatusConfiguration_type = 61 ,
	e_FTP_type  ,
	e_RTT_type  ,
	e_GatewayVoice_type  ,
	e_TimeSynchronisation_type  ,
	e_TSAStatus_type  };

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* simple.h */