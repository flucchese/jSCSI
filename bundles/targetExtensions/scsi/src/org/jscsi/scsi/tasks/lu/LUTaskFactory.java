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

package org.jscsi.scsi.tasks.lu;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.jscsi.scsi.protocol.Command;
import org.jscsi.scsi.protocol.cdb.CDB;
import org.jscsi.scsi.protocol.cdb.Inquiry;
import org.jscsi.scsi.protocol.cdb.ModeSense10;
import org.jscsi.scsi.protocol.cdb.ModeSense6;
import org.jscsi.scsi.protocol.cdb.RequestSense;
import org.jscsi.scsi.protocol.cdb.TestUnitReady;
import org.jscsi.scsi.protocol.inquiry.InquiryDataRegistry;
import org.jscsi.scsi.protocol.mode.ModePageRegistry;
import org.jscsi.scsi.protocol.sense.exceptions.IllegalRequestException;
import org.jscsi.scsi.protocol.sense.exceptions.InvalidCommandOperationCodeException;
import org.jscsi.scsi.tasks.Task;
import org.jscsi.scsi.tasks.TaskFactory;
import org.jscsi.scsi.transport.TargetTransportPort;

public class LUTaskFactory implements TaskFactory
{
   private static Logger _logger = log.getLogger(LUTaskFactory.class);

   private static Map<Class<? extends CDB>, Class<? extends LUTask>> tasks =
         new HashMap<Class<? extends CDB>, Class<? extends LUTask>>();

   private ModePageRegistry modePageRegistry;
   private InquiryDataRegistry inquiryDataRegistry;

   static
   {
      LUTaskFactory.tasks.put(Inquiry.class, InquiryTask.class);
      LUTaskFactory.tasks.put(ModeSense6.class, ModeSenseTask.class);
      LUTaskFactory.tasks.put(ModeSense10.class, ModeSenseTask.class);
      LUTaskFactory.tasks.put(RequestSense.class, RequestSenseTask.class);
      LUTaskFactory.tasks.put(TestUnitReady.class, TestUnitReadyTask.class);
   }

   public LUTaskFactory(ModePageRegistry modePageRegistry, InquiryDataRegistry inquiryDataRegistry)
   {
      this.modePageRegistry = modePageRegistry;
      this.inquiryDataRegistry = inquiryDataRegistry;
   }

   public Task getInstance(TargetTransportPort port, Command command)
         throws IllegalRequestException
   {
      Class<? extends LUTask> taskClass = tasks.get(command.getCommandDescriptorBlock().getClass());

      if (taskClass != null)
      {
         try
         {
            return taskClass.newInstance().loadTask(port, command, modePageRegistry,
                  inquiryDataRegistry);
         }
         catch (InstantiationException e)
         {
            _log.error("Initiator attempted to execute unsupported command: ("
                  + command.getCommandDescriptorBlock().getOperationCode() + ") "
                  + command.getCommandDescriptorBlock().getClass().getName());
            throw new InvalidCommandOperationCodeException();
         }
         catch (IllegalAccessException e)
         {
            _log.error("Initiator attempted to execute unsupported command: ("
                  + command.getCommandDescriptorBlock().getOperationCode() + ") "
                  + command.getCommandDescriptorBlock().getClass().getName());
            throw new InvalidCommandOperationCodeException();
         }
      }
      else
      {
         throw new InvalidCommandOperationCodeException();
      }
   }

   public boolean respondsTo(Class<? extends CDB> cls)
   {
      return tasks.containsKey(cls);
   }

   public String toString()
   {
      return "<LUTask>";
   }
}
