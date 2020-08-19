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

package org.jscsi.scsi.transport;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Random;

import org.apache.log4j.Logger;
import org.jscsi.core.scsi.Status;
import org.jscsi.scsi.protocol.sense.SenseData;
import org.jscsi.scsi.protocol.sense.SenseDataFactory;
import org.jscsi.scsi.target.Target;

public class TestTargetTransportPort implements TargetTransportPort
{
   private static Logger _logger = log.getLogger(TestTargetTransportPort.class);

   private Random rnd = new Random();

   protected long deviceCapacity;
   protected int blockSize;

   private HashMap<Long, ByteBuffer> readDataMap = new HashMap<Long, ByteBuffer>();
   private HashMap<Long, ByteBuffer> writeDataMap = new HashMap<Long, ByteBuffer>();

   public TestTargetTransportPort(long deviceCapacity, int blockSize)
   {
      this.deviceCapacity = deviceCapacity;
      this.blockSize = blockSize;
   }

   public boolean readData(Nexus nexus, long cmdRef, ByteBuffer output) throws InterruptedException
   {
      _log.debug("servicing readData request: nexus: " + nexus + ", cmdRef: " + cmdRef);
      assert this.readDataMap.containsKey(cmdRef) : "read data unavailable for crn: " + cmdRef;
      output.put(this.readDataMap.get(cmdRef).array());
      return true;
   }

   public void registerTarget(Target target)
   {
      _log.debug("servicing registerTarget request");
   }

   public void removeTarget(String targetName) throws Exception
   {
      _log.debug("servicing removeTarget request");
   }

   public void terminateDataTransfer(Nexus nexus, long commandReferenceNumber)
   {
      _log.debug("servicing terminateDataTransfer request");
   }

   public boolean writeData(Nexus nexus, long cmdRef, ByteBuffer input) throws InterruptedException
   {
      _log.debug("servicing writeData request: nexus: " + nexus + ", cmdRef: " + cmdRef);

      ByteBuffer newbuf = ByteBuffer.allocate(input.limit() - input.position());
      newbuf.put(input);
      this.writeDataMap.put(cmdRef, newbuf);
      return true;
   }

   public void writeResponse(
         Nexus nexus,
         long commandReferenceNumber,
         Status status,
         ByteBuffer senseData)
   {
      _log.debug("servicing writeResponse request: nexus: " + nexus + ", cmdRef: "
            + commandReferenceNumber);
      _log.debug("response was status: " + status);
      if (status.equals(Status.CHECK_CONDITION))
      {
         SenseData sense = null;
         try
         {
            sense = new SenseDataFactory().decode(senseData);
         }
         catch (IOException e)
         {
            _log.warn("I/O exception while decoding sense data");
         }
         _log.error("sense data: " + sense);
      }
   }

   @Override
   public String toString()
   {
      return "<TestTargetTransportPort>";
   }

   /////////////////////////////////////////////////////////////////////////////
   // utilities

   public ByteBuffer createReadData(int numBlocks, long cmdRefNum)
   {
      byte[] data = new byte[numBlocks * this.blockSize];
      this.rnd.nextBytes(data);

      ByteBuffer buffData = ByteBuffer.wrap(data);

      this.readDataMap.put(cmdRefNum, buffData);
      return buffData;
   }

   public Nexus createNexus(long taskTag)
   {
      return new Nexus("TestInitiator", "TestTarget", 0, taskTag);
   }

   /////////////////////////////////////////////////////////////////////////////
   // getters/setters

   public HashMap<Long, ByteBuffer> getReadDataMap()
   {
      return readDataMap;
   }

   public HashMap<Long, ByteBuffer> getWriteDataMap()
   {
      return writeDataMap;
   }

   public ByteBuffer removeReadBuffer(long crn)
   {
      return this.readDataMap.remove(crn);
   }

   public ByteBuffer removeWriteBuffer(long crn)
   {
      return this.writeDataMap.remove(crn);
   }
}
