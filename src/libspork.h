/*
  libspork.h

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


/*
  Spork executes a function with a given param simultaneously on n processes,
  where each process has k threads.
  So the function is cloned n*k times and executed with the same param.
  @nprocess  =  Number of processes>=1
  @ktrheads  =  Number of threads>=1
  @func      =  function pointer to execute
  @param     =  params for func
*/
int spork(int, int, void *(*func)(void *), void *);

