/**
 * Copyright (c) 2012, University of Konstanz, Distributed Systems Group
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of Konstanz nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//Cleversafe open-source code header - Version 1.1 - December 1, 2006
//
//Cleversafe Dispersed Storage(TM) is software for secure, private and
//reliable storage of the world's data using information dispersal.
//
//Copyright (C) 2005-2007 Cleversafe, Inc.
//
//This program is free software; you can redistribute it and/or
//modify it under the terms of the GNU General Public License
//as published by the Free Software Foundation; either version 2
//of the License, or (at your option) any later version.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
//along with this program; if not, write to the Free Software
//Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
//USA.
//
//Contact Information: 
// Cleversafe, 10 W. 35th Street, 16th Floor #84,
// Chicago IL 60616
// email: licensing@cleversafe.org
//
//END-OF-HEADER
//-----------------------
//@author: John Quigley <jquigley@cleversafe.com>
//@date: January 1, 2008
//---------------------

package org.jscsi.scsi.tasks.buffered;

import java.nio.ByteBuffer;

import static org.junit.Assert.*;

import org.apache.log4j.Logger;
import org.jscsi.scsi.protocol.cdb.CDB;
import org.jscsi.scsi.protocol.cdb.ReadCapacity10;
import org.jscsi.scsi.protocol.cdb.ReadCapacity16;
import org.junit.Test;

public class BufferedReadCapacityTaskTest extends BufferTestTask
{
   private static Logger _logger = Logger.getLogger(BufferedReadCapacityTaskTest.class);

   private static int cmdRef = 0;

   ///////////////////////////////////////////////////////////////////////////// 

   @Test
   public void testReadCapacity10inMemory()
   {
      _logger.debug("********** READ CAPACITY 10 MEMORY **********");
      CDB cdb = new ReadCapacity10(false, 0);
      this.submitMemoryTask(cdb, cmdRef);
      verifyInputBufferCapacity10();
      cmdRef++;
   }

   @Test
   public void testReadCapacity10inFile()
   {
      _logger.debug("********** READ CAPACITY 10 FILE **********");
      CDB cdb = new ReadCapacity10(false, 0);
      this.submitFileTask(cdb, cmdRef);
      verifyInputBufferCapacity10();
      cmdRef++;
   }

   @Test
   public void testReadCapacity16inMemory()
   {
      _logger.debug("********** READ CAPACITY 16 MEMORY **********");
      CDB cdb = new ReadCapacity16(32, false, 0);
      this.submitMemoryTask(cdb, cmdRef);
      verifyInputBufferCapacity16();
      cmdRef++;
   }

   @Test
   public void testReadCapacity16inFile()
   {
      _logger.debug("********** READ CAPACITY 16 FILE **********");
      CDB cdb = new ReadCapacity16(32, false, 0);
      this.submitFileTask(cdb, cmdRef);
      verifyInputBufferCapacity16();
      cmdRef++;
   }

   public void verifyInputBufferCapacity10()
   {
      final int expectedNumberOfBlocks = STORE_CAPACITY / STORE_BLOCK_SIZE;

      ByteBuffer inputBuffer = this.getWriteData(cmdRef);

      assertNotNull(inputBuffer);

      inputBuffer.rewind();

      final int returnedNumberOfBlocks = inputBuffer.getInt();

      final int returnedBlockLength = inputBuffer.getInt();

      assertEquals(expectedNumberOfBlocks, returnedNumberOfBlocks);

      assertEquals(returnedBlockLength, STORE_BLOCK_SIZE);
   }

   /**
    * Whitebox test of ReadCapacity16
    */
   public void verifyInputBufferCapacity16()
   {
      final long expectedNumberOfBlocks = STORE_CAPACITY / STORE_BLOCK_SIZE;

      ByteBuffer inputBuffer = this.getWriteData(cmdRef);

      assertNotNull(inputBuffer);

      inputBuffer.rewind();

      final long returnedNumberOfBlocks = inputBuffer.getLong();

      final int returnedBlockLength = inputBuffer.getInt();

      assertEquals(expectedNumberOfBlocks, returnedNumberOfBlocks);

      assertEquals(returnedBlockLength, STORE_BLOCK_SIZE);
   }
}
