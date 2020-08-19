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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.nio.ByteBuffer;
import java.util.Random;

import org.apache.log4j.Logger;
import org.jscsi.scsi.protocol.cdb.CDB;
import org.jscsi.scsi.protocol.cdb.Read10;
import org.jscsi.scsi.protocol.cdb.Read12;
import org.jscsi.scsi.protocol.cdb.Read16;
import org.jscsi.scsi.protocol.cdb.Read6;
import org.junit.Test;

public class BufferedReadTaskTest extends BufferTestTask
{
   private static Logger _logger = log.getLogger(BufferedReadTaskTest.class);

   private static final int READ_BLOCKS = 10;

   private static int cmdRef = 0;

   private Random rnd = new Random();

   /////////////////////////////////////////////////////////////////////////////

   @Test
   public void testRead6inMemory()
   {
      _log.debug("********** READ6 MEMORY **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read6(false, true, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitMemoryTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead6inFile()
   {
      _log.debug("********** READ6 FILE **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read6(false, true, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitFileTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead10inMemory()
   {
      _log.debug("********** READ10 MEMORY **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read10(0, false, false, false, false, false, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitMemoryTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead10inFile()
   {
      _log.debug("********** READ10 FILE **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read10(0, false, false, false, false, false, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitFileTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead12inMemory()
   {
      _log.debug("********** READ12 MEMORY **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read12(0, false, false, false, false, false, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitMemoryTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead12inFile()
   {
      _log.debug("********** READ12 FILE **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read12(0, false, false, false, false, false, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitFileTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead16inMemory()
   {
      _log.debug("********** READ16 MEMORY **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read16(0, false, false, false, false, false, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitMemoryTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   @Test
   public void testRead16inFile()
   {
      _log.debug("********** READ16 FILE **********");
      int lba = generateRandomLBA();
      CDB cdb = new Read16(0, false, false, false, false, false, lba, READ_BLOCKS);
      ByteBuffer data =
            this.writeDeviceData(lba * STORE_BLOCK_SIZE, READ_BLOCKS * STORE_BLOCK_SIZE, cmdRef);
      this.submitFileTask(cdb, cmdRef);
      verifyInputBuffer(data);
      this.purgeDeviceData();
      cmdRef++;
   }

   /**
    * Verify that the data that was placed into the device's buffer matches
    * what was set into the InputBuffer after calling Read
    * 
    * @param data The data written to the device
    */
   private void verifyInputBuffer(ByteBuffer data)
   {
      final int bytesWritten = READ_BLOCKS * STORE_BLOCK_SIZE;

      ByteBuffer writtenBuffer = this.getWriteData(cmdRef);

      assertNotNull(data);
      assertNotNull(writtenBuffer);

      data.rewind();
      writtenBuffer.rewind();

      for (int i = 0; i < bytesWritten; i++)
      {
         byte d = data.get();
         byte w = writtenBuffer.get();

         assertEquals(d, w);
      }
   }

   private int generateRandomLBA()
   {
      return Math.abs(rnd.nextInt()) % ((STORE_CAPACITY / STORE_BLOCK_SIZE) - READ_BLOCKS);
   }

}
