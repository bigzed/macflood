/*
  macflood.c

  Reimplementation of C port macof.c from PerlNet::RawIP distribution.

  Perl macof originally written by Ian Vitek <ian.vitek@infosec.se>
  C macof originally writen by Dug Song <dugsong@monkey.org>.

  Copyright (c) 2011 Steve Dierker <steve.dierker@obstkiste.org>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  he Free Software Foundation, either version 3 of the License, or
  ())at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define VERSION   "0.1"

// Address constants
u_int8_t empty_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
u_int8_t empty_ip[4]  = {0x00, 0x00, 0x00, 0x00};

// Input Arguments from cmd-line
char            *intf = NULL;
int32_t         repeat = -1;
u_int8_t        verbose = 0;
int32_t         threads = -1;
int32_t         processes = 1;

