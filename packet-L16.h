/* packet-link16.h
 * Routines for Link 16 message dissection (MIL-STD-6016)
 * William Robertson <aliask@gmail.com>
 * Peter Ross <peter.ross@dsto.defence.gov.au>
 * updated by By Pierre-Henri Bourdelle 
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef __PACKET_LINK16_H__
#define __PACKET_LINK16_H__
#

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern const value_string Link16_NPG_Strings[];
typedef struct {
	gint active;
	gint stn;
	gint npg;
	gint net;
	gint tn;
	gint node;
} Link16GenericHeader;
typedef struct {
    gint label;
    gint sublabel;
    gint extension;
	Link16GenericHeader header;
} Link16State;

#ifdef __cplusplus
}
#endif /* __cplusplus */


#endif /* __PACKET_LINK16_H__ */
