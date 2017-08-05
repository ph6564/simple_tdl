/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from ../../tools/make-dissector-reg.py.
 */

#include "config.h"

#include <gmodule.h>

#include "moduleinfo.h"

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#ifndef ENABLE_STATIC
WS_DLL_PUBLIC_DEF void plugin_register (void);
WS_DLL_PUBLIC_DEF const gchar version[] = VERSION;

/* Start the functions we need for the plugin stuff */

WS_DLL_PUBLIC_DEF void
plugin_register (void)
{
    {extern void proto_register_L16 (void); proto_register_L16 ();}
    {extern void proto_register_dis_simple (void); proto_register_dis_simple ();}
    {extern void proto_register_l11 (void); proto_register_l11 ();}
    {extern void proto_register_simple (void); proto_register_simple ();}
}

WS_DLL_PUBLIC_DEF void plugin_reg_handoff(void);

WS_DLL_PUBLIC_DEF void
plugin_reg_handoff(void)
{
    {extern void proto_reg_handoff_dis_simple (void); proto_reg_handoff_dis_simple ();}
    {extern void proto_reg_handoff_l11 (void); proto_reg_handoff_l11 ();}
    {extern void proto_reg_handoff_simple (void); proto_reg_handoff_simple ();}
}
#endif
