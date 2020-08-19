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

package org.jscsi.scsi.tasks;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicBoolean;

import org.apache.log4j.Logger;
import org.jscsi.core.scsi.Status;
import org.jscsi.scsi.protocol.Command;
import org.jscsi.scsi.protocol.cdb.CDB;
import org.jscsi.scsi.protocol.cdb.ParameterCDB;
import org.jscsi.scsi.protocol.cdb.TransferCDB;
import org.jscsi.scsi.protocol.inquiry.InquiryDataRegistry;
import org.jscsi.scsi.protocol.mode.ModePageRegistry;
import org.jscsi.scsi.protocol.sense.exceptions.SenseException;
import org.jscsi.scsi.protocol.sense.exceptions.SynchronousDataTransferErrorException;
import org.jscsi.scsi.transport.TargetTransportPort;

//TODO: Describe class or interface
public abstract class AbstractTask implements Task
{
   private static Logger _logger = log.getLogger(AbstractTask.class);

   private TargetTransportPort targetTransportPort;
   private Command command;
   private ModePageRegistry modePageRegistry;
   private InquiryDataRegistry inquiryDataRegistry;
   private String name = "DefaultTaskName";

   private Thread thread = null;

   /**
    * Abort variable specifies whether task can be aborted or is currently aborted.
    * <p>
    * <ul>
    * <li>If abort is true, task is already aborted or can no longer be aborted.</li>
    * <li>If abort is false, task is not aborted and can be aborted.</li>
    * </ul>
    * <p>
    * The {@link #abort()} method will fail if the this is true. The {@link #run()} method will not
    * enter the {@link #writeResponse(Status, ByteBuffer)} phase. However, abort is not polled.
    * Instead, we check {@link Thread#isInterrupted()}.
    */
   private final AtomicBoolean abort = new AtomicBoolean(false);

   /////////////////////////////////////////////////////////////////////////////
   // abstract methods

   protected abstract void execute() throws InterruptedException, SenseException;

   /////////////////////////////////////////////////////////////////////////////
   // constructors

   protected AbstractTask()
   {
   }

   protected AbstractTask(String name)
   {
      this.name = name;
   }

   protected AbstractTask(
         String name,
         TargetTransportPort targetPort,
         Command command,
         ModePageRegistry modePageRegistry,
         InquiryDataRegistry inquiryDataRegistry)
   {
      this.name = name;
      this.targetTransportPort = targetPort;
      this.command = command;
      this.modePageRegistry = modePageRegistry;
      this.inquiryDataRegistry = inquiryDataRegistry;
   }

   /////////////////////////////////////////////////////////////////////////////
   // operations

   protected final Task load(
         TargetTransportPort targetPort,
         Command command,
         ModePageRegistry modePageRegistry,
         InquiryDataRegistry inquiryDataRegistry)
   {
      this.command = command;
      this.targetTransportPort = targetPort;
      this.modePageRegistry = modePageRegistry;
      this.inquiryDataRegistry = inquiryDataRegistry;
      return this;
   }

   public final boolean abort()
   {
      if (abort.compareAndSet(false, true))
      {
         // If abort is false the task can be aborted because it is neither
         // already aborted nor in the writeResponse() phase. Abort is now set as true.

         // We interrupt the thread executing the task and terminate any outstanding
         // data. With luck, writeData() and readData() methods will not begin if
         // the thread is interrupted. If interrupt() and terminateDataTransfer()
         // occur between the interrupt check and the transfer call to the transport layer
         // the transport layer will receive a request for an already terminated nexus.
         // The transport port interface guarantees that InterruptedException will always be
         // thrown from the transfer methods in this case.
         this.thread.interrupt();
         this.targetTransportPort.terminateDataTransfer(this.command.getNexus(),
               this.command.getCommandReferenceNumber());

         return true;
      }
      else
      {
         // If abort is true the task is already aborted or is in the writeResponse() phase. We
         // can no longer abort and the abort value remains set as true.
         return false;
      }
   }

   public final void run()
   {
      this.thread = Thread.currentThread();
      try
      {
         this.execute();
      }
      catch (SenseException e)
      {
         _log.debug("sense exception caught handling command: " + command);
         // Write response with a CHECK CONDITION status.
         this.targetTransportPort.writeResponse(this.command.getNexus(),
               this.command.getCommandReferenceNumber(), Status.CHECK_CONDITION,
               ByteBuffer.wrap(e.encode()));
      }
      catch (InterruptedException e)
      {
         _log.info("Task " + name + " was aborted.");
         // Task was aborted, don't do anything
      }
      catch (Exception e)
      {
         _log.error("Task " + name + " encountered an exception while executing", e);
      }
   }

   protected final boolean readData(ByteBuffer output) throws InterruptedException,
         SynchronousDataTransferErrorException
   {
      if (Thread.interrupted())
         throw new InterruptedException();

      return this.targetTransportPort.readData(this.command.getNexus(),
            this.command.getCommandReferenceNumber(), output);
   }

   protected final boolean writeData(ByteBuffer input) throws InterruptedException,
         SynchronousDataTransferErrorException
   {
      if (Thread.interrupted())
      {
         _log.debug("calling writeData on the TransportPort was interrupted during Task execution");
         throw new InterruptedException();
      }

      return this.targetTransportPort.writeData(this.command.getNexus(),
            this.command.getCommandReferenceNumber(), input);
   }

   protected final boolean writeData(byte[] input) throws InterruptedException,
         SynchronousDataTransferErrorException
   {
      if (Thread.interrupted())
         throw new InterruptedException();

      // check how much data may be returned
      CDB cdb = this.command.getCommandDescriptorBlock();
      long transferLength = 0;
      if (cdb instanceof TransferCDB)
      {
         transferLength = ((TransferCDB) cdb).getTransferLength();
      }
      else if (cdb instanceof ParameterCDB)
      {
         transferLength = ((ParameterCDB) cdb).getAllocationLength();
      }
      // If the CDB is not a transfer or parameter CDB no data should be transfered

      // We allocate a byte buffer of transfer length and write either all input data
      // or up to the transfer length in input data.
      ByteBuffer data = ByteBuffer.allocate((int) Math.min(transferLength, input.length));
      data.put(input, 0, (int) Math.min(transferLength, input.length));
      data.rewind();

      if (Thread.interrupted())
         throw new InterruptedException();

      return this.targetTransportPort.writeData(this.command.getNexus(),
            this.command.getCommandReferenceNumber(), data);
   }

   protected final void writeResponse(Status status, ByteBuffer senseData)
   {
      if (abort.compareAndSet(false, true))
      {
         // If abort is false the task can enter the writeResponse() phase. Abort is now
         // set as true to indicate that abort() can no longer succeed.
         this.getTargetTransportPort().writeResponse(command.getNexus(),
               command.getCommandReferenceNumber(), status, senseData);
      }
      else
      {
         // If abort is true the task has been aborted and no data shall be written to
         // the target transport port. Abort remains set as true.
         _log.debug("task was aborted, no response to be written: " + this);
         return;
      }
   }

   /////////////////////////////////////////////////////////////////////////////
   // getters/setters

   public final Command getCommand()
   {
      return this.command;
   }

   public final TargetTransportPort getTargetTransportPort()
   {
      return this.targetTransportPort;
   }

   protected final InquiryDataRegistry getInquiryDataRegistry()
   {
      return this.inquiryDataRegistry;
   }

   protected final ModePageRegistry getModePageRegistry()
   {
      return this.modePageRegistry;
   }

   public final String getName()
   {
      return this.name;
   }

   public void setName(final String name)
   {
      this.name = name;
   }

   @Override
   public String toString()
   {
      return "<Task name: " + this.getName() + ", command: " + this.command + ", target-port: "
            + this.targetTransportPort + ">";
   }
}
