/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from make-plugin-reg.py.
 */

#include "config.h"

#include <gmodule.h>

/* plugins are DLLs on Windows */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include "epan/proto.h"

void proto_register_L16(void);
void proto_register_dis_simple(void);
void proto_register_l11(void);
void proto_register_simple(void);
void proto_reg_handoff_dis_simple(void);
void proto_reg_handoff_l11(void);
void proto_reg_handoff_simple(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_L16;

    plug_L16.register_protoinfo = proto_register_L16;
    plug_L16.register_handoff = NULL;
    proto_register_plugin(&plug_L16);
    static proto_plugin plug_dis_simple;

    plug_dis_simple.register_protoinfo = proto_register_dis_simple;
    plug_dis_simple.register_handoff = proto_reg_handoff_dis_simple;
    proto_register_plugin(&plug_dis_simple);
    static proto_plugin plug_l11;

    plug_l11.register_protoinfo = proto_register_l11;
    plug_l11.register_handoff = proto_reg_handoff_l11;
    proto_register_plugin(&plug_l11);
    static proto_plugin plug_simple;

    plug_simple.register_protoinfo = proto_register_simple;
    plug_simple.register_handoff = proto_reg_handoff_simple;
    proto_register_plugin(&plug_simple);
}
