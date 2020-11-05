/**
 * Copyright (c) 2012, University of Konstanz, Distributed Systems Group All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met: * Redistributions of source code must retain the above copyright notice, this list of
 * conditions and the following disclaimer. * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation and/or other materials provided with the
 * distribution. * Neither the name of the University of Konstanz nor the names of its contributors may be used to
 * endorse or promote products derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.jscsi.parser;


import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.DigestException;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.jscsi.exception.InternetSCSIException;
import org.jscsi.parser.datasegment.AbstractDataSegment;
import org.jscsi.parser.datasegment.IDataSegmentIterator.IDataSegmentChunk;
import org.jscsi.parser.digest.IDigest;


/**
 * <h1>ProtocolDataUnit</h1>
 * <p>
 * This class encapsulates a Protocol Data Unit (PDU), which is defined in the iSCSI Standard (RFC 3720).
 * 
 * @author Volker Wildi
 */
public final class ProtocolDataUnit {

    private static final Logger log = LogManager.getLogger(ProtocolDataUnit.class);

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /** The initial size of the Additional Header Segment. */
    private static final int AHS_INITIAL_SIZE = 0;

    private static final int TRANSFER_THREADS = 10;

    private static final ExecutorService transferExecutor;

    private static final Set<SocketChannel> blockedSockets;
    
    private static final Lock semaphorsLock;

    private static final Condition semaphorsCond;

    static {
    	transferExecutor = Executors.newFixedThreadPool(TRANSFER_THREADS);
    	blockedSockets = new HashSet<>();
    	semaphorsLock = new ReentrantLock();
    	semaphorsCond = semaphorsLock.newCondition();
    }
    
    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /** The Basic Header Segment of this PDU. */
    private final BasicHeaderSegment basicHeaderSegment;

    /** The Additional Header Segment 1...n (optional) of this PDU. */
    private final AbstractList<AdditionalHeaderSegment> additionalHeaderSegments;

    /**
     * The (optional) Data Segment contains PDU associated data. Its payload effective length is provided in the BHS
     * field - <code>DataSegmentLength</code>. The Data Segment is also padded to multiple of a <code>4</code> byte
     * words.
     */
    private ByteBuffer dataSegment;

    private boolean onGoingRead;
    private boolean additionalHeaderReady;
    private boolean dataHeaderReady;

    private Lock readLock;
    private Condition readCond;
    
    /**
     * Optional header and data digests protect the integrity of the header and data, respectively. The digests, if
     * present, are located, respectively, after the header and PDU-specific data, and cover respectively the header and
     * the PDU data, each including the padding bytes, if any.
     * <p>
     * <b>The existence and type of digests are negotiated during the Login Phase. </b>
     * <p>
     * The separation of the header and data digests is useful in iSCSI routing applications, in which only the header
     * changes when a message is forwarded. In this case, only the header digest should be recalculated.
     * <p>
     * Digests are not included in data or header length fields.
     * <p>
     * A zero-length Data Segment also implies a zero-length data-digest.
     */

    /** Digest of the header of this PDU. */
    private IDigest headerDigest;

    /** Digest of the data segment of this PDU. */
    private IDigest dataDigest;

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /**
     * Default constructor, creates a new, empty ProtcolDataUnit object.
     * 
     * @param initHeaderDigest The instance of the digest to use for the Basic Header Segment protection.
     * @param initDataDigest The instance of the digest to use for the Data Segment protection.
     */
    public ProtocolDataUnit (final IDigest initHeaderDigest, final IDigest initDataDigest) {
        basicHeaderSegment = new BasicHeaderSegment();
        headerDigest = initHeaderDigest;

        additionalHeaderSegments = new ArrayList<>(AHS_INITIAL_SIZE);

        dataSegment = ByteBuffer.allocate(0);
        dataDigest = initDataDigest;
        
        readLock = new ReentrantLock();
        readCond = readLock.newCondition();
    }

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /**
     * Serialize all informations of this PDU object to its byte representation.
     * 
     * @return The byte representation of this PDU.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     * @throws DigestException 
     */
    public final ByteBuffer serialize() throws InternetSCSIException {
    	return serialize(true);
    }

    /**
     * Serialize selected informations of this PDU object to its byte representation.
     * 
     * @param boolean specifies weather the data segment should be included or not
     * @return The byte representation of this PDU.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     * @throws DigestException 
     * @throws IOException if an I/O error occurs.
     */
    public final ByteBuffer serialize(boolean includeDataSegment) throws InternetSCSIException {
        basicHeaderSegment.getParser().checkIntegrity();

        final ByteBuffer pdu = ByteBuffer.allocate(calcSize(includeDataSegment));

        int offset = 0;
        offset += basicHeaderSegment.serialize(pdu, offset);

        // write basic header digest
        if (basicHeaderSegment.getParser().canHaveDigests() &&
        	calculateDigest(pdu, 0, BasicHeaderSegment.BHS_FIXED_SIZE, headerDigest)) {
        	pdu.putInt((int) headerDigest.getValue());
            offset += headerDigest.getSize();
        }

        if (log.isTraceEnabled()) {
            log.trace("Serialized Basic Header Segment:\n" + toString());
        }

        offset += serializeAdditionalHeaderSegments(pdu, offset);

		if (includeDataSegment) {
	        // serialize data segment
	        serializeDataSegment(pdu, offset);
	        if (basicHeaderSegment.getParser().canHaveDigests()) {
	        	dataSegment.rewind();
	        	if (calculateDigest(dataSegment, 0, dataSegment.limit(), dataDigest)) {
		        	pdu.putInt((int) dataDigest.getValue());
	        	}
	        }
		}

        return (ByteBuffer) pdu.rewind();
    }

    /**
     * Deserializes (parses) a given byte representation of a PDU to an PDU object.
     * 
     * @param pdu The byte representation of an PDU to parse.
     * @return The number of bytes, which are serialized.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     * @throws IOException if an I/O error occurs.
     * @throws DigestException There is a mismatch of the digest.
     */
    public final int deserialize(final ByteBuffer pdu) throws InternetSCSIException, DigestException {
        int offset = deserializeBasicHeaderSegmentAndDigest(pdu);

        offset += deserializeAdditionalHeaderSegments(pdu, offset);

        offset += deserializeDataSegmentAndDigest(pdu, offset);

        basicHeaderSegment.getParser().checkIntegrity();

        return offset;
    }

    /**
     * Deserializes a given array starting from offset <code>0</code> and store the informations in the
     * BasicHeaderSegment object..
     * 
     * @param bhs The array to read from.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     * @throws DigestException There is a mismatch of the digest.
     */
    private final int deserializeBasicHeaderSegmentAndDigest (final ByteBuffer bhs) throws InternetSCSIException {
        int len = basicHeaderSegment.deserialize(this, bhs);

        // read header digest and validate
        if (basicHeaderSegment.getParser().canHaveDigests() &&
        	calculateDigest(bhs, bhs.position() - BasicHeaderSegment.BHS_FIXED_SIZE, BasicHeaderSegment.BHS_FIXED_SIZE, headerDigest)) {
            len += headerDigest.getSize();
        }

        if (log.isTraceEnabled()) {
            log.trace("Deserialized Basic Header Segment:\n" + toString());
        }

        return len;
    }

    /**
     * Serialize all the contained additional header segments to the destination array starting from the given offset.
     * 
     * @param dst The destination array to write in.
     * @param offset The offset to start to write in <code>dst</code>.
     * @return The written length.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     */
    private final int serializeAdditionalHeaderSegments (final ByteBuffer dst, final int offset) throws InternetSCSIException {
        int off = offset;
        for (AdditionalHeaderSegment ahs : additionalHeaderSegments) {
            off += ahs.serialize(dst, off);
        }

        return off - offset;
    }

    /**
     * Deserializes a array (starting from offset <code>0</code>) and store the informations to the
     * <code>AdditionalHeaderSegment</code> object.
     * 
     * @param pdu The array to read from.
     * @return The length of the read bytes.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     */
    private final int deserializeAdditionalHeaderSegments (final ByteBuffer pdu) throws InternetSCSIException {
        return deserializeAdditionalHeaderSegments(pdu, 0);
    }

    /**
     * Deserializes a array (starting from the given offset) and store the informations to the
     * <code>AdditionalHeaderSegment</code> object.
     * 
     * @param pdu The <code>ByteBuffer</code> to read from.
     * @param offset The offset to start from.
     * @return The length of the written bytes.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     */
    private final int deserializeAdditionalHeaderSegments (final ByteBuffer pdu, final int offset) throws InternetSCSIException {
        // parsing Additional Header Segment
        int off = offset;
        int ahsLength = basicHeaderSegment.getTotalAHSLength();
        while (ahsLength != 0) {
            final AdditionalHeaderSegment tmpAHS = new AdditionalHeaderSegment();
            tmpAHS.deserialize(pdu, off);

            additionalHeaderSegments.add(tmpAHS);
            ahsLength -= tmpAHS.getLength();

            off += tmpAHS.getSpecificField().position();
        }

        return off - offset;
    }

    /**
     * Serializes the data segment (binary or key-value pairs) to a destination array, staring from offset to write.
     * 
     * @param dst The array to write in.
     * @param offset The start offset to start from in <code>dst</code>.
     * @return The written length.
     * @throws InternetSCSIException If any violation of the iSCSI-Standard emerge.
     */
    public final int serializeDataSegment (final ByteBuffer dst, final int offset) {
        dataSegment.rewind();
        dst.position(offset);
        dst.put(dataSegment);

        return dataSegment.limit();
    }

    /**
     * Deserializes a array (starting from the given offset) and store the informations to the Data Segment.
     * 
     * @param pdu The array to read from.
     * @param offset The offset to start from.
     * @return The length of the written bytes.
     * @throws DigestException There is a mismatch of the digest.
     */
    private final int deserializeDataSegmentAndDigest (final ByteBuffer pdu, final int offset) {
        final int length = basicHeaderSegment.getDataSegmentLength();

        if (dataSegment == null || dataSegment.limit() < length) {
            dataSegment = ByteBuffer.allocate(AbstractDataSegment.getTotalLength(length));
        }
        dataSegment.put(pdu);

        dataSegment.flip();

        // read data segment digest and validate
        if (basicHeaderSegment.getParser().canHaveDigests()) {
        	calculateDigest(pdu, offset, length, dataDigest);
        }

        if (dataSegment == null) {
            return 0;
        } else {
            return dataSegment.limit();
        }
    }

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /**
     * Writes this <code>ProtocolDataUnit</code> object to the given <code>SocketChannel</code>.
     * 
     * @param sChannel <code>SocketChannel</code> to write to.
     * @return The number of bytes written, possibly zero.
     * @throws InternetSCSIException if any violation of the iSCSI-Standard emerge.
     * @throws IOException if an I/O error occurs.
     * @throws DigestException 
     */
    public final int write(SocketChannel sChannel) throws InternetSCSIException, IOException {
        // print debug informations
        if (log.isTraceEnabled()) {
            log.trace(basicHeaderSegment.getParser().getShortInfo());
        }

        // Send headers
        ByteBuffer headers = serialize(false);
        int length = 0;
        while (length < headers.limit()) {
            length += sChannel.write(headers);
        }

        // Send data segment
        length = 0;
        dataSegment.rewind();
        while (length < dataSegment.limit()) {
            length += sChannel.write(dataSegment);
        }

        ByteBuffer padding = ByteBuffer.allocate(AbstractDataSegment.calcPadding(length));
        length = 0;
        while (length < padding.limit()) {
            length += sChannel.write(padding);
        }

        // Send data segment digest, if needed
        if (basicHeaderSegment.getParser().canHaveDigests()) {
        	dataSegment.rewind();
        	if (calculateDigest(dataSegment, 0, dataSegment.limit(), dataDigest)) {
                ByteBuffer dataDigestBuffer = ByteBuffer.allocate(dataDigest.getSize());
                dataDigestBuffer.putInt((int) headerDigest.getValue());
                dataDigestBuffer.rewind();
                length = 0;
                while (length < dataDigestBuffer.limit()) {
                    length += sChannel.write(dataDigestBuffer);
                }
                log.debug(length+" bytes written for the data digest");
        	}
        }

        return length;
    }

    /**
     * Reads from the given <code>SocketChannel</code> all the neccassary bytes to fill this PDU.
     * 
     * @param sChannel <code>SocketChannel</code> to read from.
     * @return The number of bytes, possibly zero,or <code>-1</code> if the channel has reached end-of-stream
     * @throws IOException if an I/O error occurs.
     * @throws InternetSCSIException if any violation of the iSCSI-Standard emerge.
     * @throws DigestException if a mismatch of the digest exists.
     */
    public final void read(final SocketChannel sChannel) {
    	dataHeaderReady = false;
    	onGoingRead = true;

    	// Wait if current socket is being used by another reading thread
    	semaphorsLock.lock();
    	try {
       		while (blockedSockets.contains(sChannel)) {
       			semaphorsCond.awaitUninterruptibly();
       		}
       		blockedSockets.add(sChannel);
    	} finally {
        	semaphorsLock.unlock();
    	}
    	
		log.trace("Starting synchronous read at channel "+sChannel);
        // read Basic Header Segment first to determine the total length of this
        // Protocol Data Unit.
        clear();

		try {
	        final ByteBuffer bhs = ByteBuffer.allocate(BasicHeaderSegment.BHS_FIXED_SIZE);
	        int len = 0;
	        while (len < BasicHeaderSegment.BHS_FIXED_SIZE) {
	            len += sChannel.read(bhs);
	        }
	        bhs.flip();
	        deserializeBasicHeaderSegmentAndDigest(bhs);

	        // print debug informations
	        if (log.isTraceEnabled()) {
	            log.trace(basicHeaderSegment.getParser().getShortInfo());
	        }
	        
	    	transferExecutor.submit(() -> {
	    		try {
	    			log.trace("Starting asynchronous read at channel "+sChannel);

	    			// check for further reading
	    	        if (getBasicHeaderSegment().getTotalAHSLength() > 0) {
	    	            final ByteBuffer ahs = ByteBuffer.allocate(basicHeaderSegment.getTotalAHSLength());
	    	            int ahsLength = 0;
	    	            while (ahsLength < getBasicHeaderSegment().getTotalAHSLength()) {
	    	                ahsLength += sChannel.read(ahs);
	    	            }
	    				log.trace("Additional header read. Deserializing it...");
	    	            ahs.flip();

	    	            deserializeAdditionalHeaderSegments(ahs);
	    	            readLock.lock();
	    	            try {
	    	            	additionalHeaderReady = true;
	    	            	readCond.signalAll();
	    	            } finally {
	    	                readLock.unlock();
	    	            }
	    				log.trace("Additional header ready.");
	    	        }

	    	        if (basicHeaderSegment.getDataSegmentLength() > 0) {
		                readLock.lock();
		                try {
		                	while (dataSegment == null) {
		    	    			log.trace("Waiting for data segment buffer...");
			                	readCond.awaitUninterruptibly();
		                	};
	    	    			log.trace("Data segment buffer set.");
		                } finally {
		                    readLock.unlock();
		                }
		                int dataSegmentLength = 0;
		    			log.trace("Starting to read data segment...");
		                while (dataSegmentLength < basicHeaderSegment.getDataSegmentLength()) {
		                    dataSegmentLength += sChannel.read(dataSegment);
		                }
		    			log.trace("Data segment read.");
		                dataSegment.flip();
		                
		                readLock.lock();
		                try {
		                	dataHeaderReady = true;
		                	readCond.signalAll();
		                } finally {
		                    readLock.unlock();
		                }
		    			log.trace("Data segment ready.");
		            }
	    		} catch (IOException | InternetSCSIException e) {
	    			log.warn("Problems receiving PDU", e);
	    		}
	            readLock.lock();
	            try {
	            	onGoingRead = false;
	            	readCond.signalAll();
	            } finally {
	                readLock.unlock();
	            }
	        	semaphorsLock.lock();
	        	try {
	           		blockedSockets.remove(sChannel);
	           		semaphorsCond.signalAll();
	        	} finally {
	            	semaphorsLock.unlock();
	        	}
	    	});
		} catch (IOException | InternetSCSIException e) {
			log.warn("Problems receiving PDU", e);
            readLock.lock();
            try {
            	onGoingRead = false;
            	readCond.signalAll();
            } finally {
                readLock.unlock();
            }
        	semaphorsLock.lock();
        	try {
           		blockedSockets.remove(sChannel);
           		semaphorsCond.signalAll();
        	} finally {
            	semaphorsLock.unlock();
        	}
		}
    }

    public final void writeToBuffer(ByteBuffer dataSegment) {
        readLock.lock();
        try {
            this.dataSegment = dataSegment;
			log.trace("Setting mapped buffer for data segment.");
        	readCond.signalAll();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Clears all stored content of this ProtocolDataUnit object.
     */
    public final void clear () {
        basicHeaderSegment.clear();

        headerDigest.reset();

        additionalHeaderSegments.clear();

        dataSegment.clear();
        dataSegment.flip();

        dataDigest.reset();
    }

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /**
     * Returns the Basic Header Segment contained in this PDU.
     * 
     * @return The Basic Header Segment.
     * @see BasicHeaderSegment
     */
    public final BasicHeaderSegment getBasicHeaderSegment () {
       	return basicHeaderSegment;
    }

    /**
     * Returns an iterator to all contained Additional Header Segment in this PDU.
     * 
     * @return The iterator to the contained Additional Header Segment.
     * @see AdditionalHeaderSegment
     */
    public final Iterator<AdditionalHeaderSegment> getAdditionalHeaderSegments () {
        readLock.lock();
        try {
        	while (!additionalHeaderReady && onGoingRead) {
            	readCond.awaitUninterruptibly();
        	}

        	return additionalHeaderSegments.iterator();
        } finally {
            readLock.unlock();
        }
    }

    /**
     * Gets the data segment in this PDU.
     * 
     * @return The data segment of this <code>ProtocolDataUnit</code> object.
     */
    public final ByteBuffer getDataSegment() {
        readLock.lock();
        try {
            dataSegment = ByteBuffer.allocate(AbstractDataSegment.getTotalLength(basicHeaderSegment.getDataSegmentLength()));
        	readCond.signalAll();
        	while (!dataHeaderReady && onGoingRead) {
            	readCond.awaitUninterruptibly();
        	}

        	return dataSegment;
        } finally {
            readLock.unlock();
        }
    }

    public final void setDataSegment (final ByteBuffer dataSegment) {
        this.dataSegment = dataSegment;
        basicHeaderSegment.setDataSegmentLength(dataSegment.capacity());
    }

    /**
     * Sets a new data segment in this PDU.
     * 
     * @param chunk The new data segment of this <code>ProtocolDataUnit</code> object.
     */
    public final void setDataSegment (final IDataSegmentChunk chunk) {
        if (chunk == null) { throw new NullPointerException(); }

        dataSegment = ByteBuffer.allocate(chunk.getTotalLength());
        dataSegment.put(chunk.getData());
        basicHeaderSegment.setDataSegmentLength(chunk.getLength());
    }

    /**
     * Returns the instance of the used digest algorithm for the header.
     * 
     * @return The instance of the header digest.
     */
    public final IDigest getHeaderDigest () {
        return headerDigest;
    }

    /**
     * Sets the digest of the header to use for data integrity.
     * 
     * @param newHeaderDigest An instance of the new header digest.
     */
    public final void setHeaderDigest (final IDigest newHeaderDigest) {
        headerDigest = newHeaderDigest;
    }

    /**
     * Returns the instance of the used digest algorithm for the data segment.
     * 
     * @return The instance of the data digest.
     */
    public final IDigest getDataDigest () {
        return dataDigest;
    }

    /**
     * Sets the digest of the data segment to use for data integrity.
     * 
     * @param newDataDigest An instance of the new data segment digest.
     */
    public final void setDataDigest (final IDigest newDataDigest) {
        dataDigest = newDataDigest;
    }

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /** {@inheritDoc} */
    @Override
    public final String toString () {

        final StringBuilder sb = new StringBuilder(Constants.LOG_INITIAL_SIZE);

        sb.append(basicHeaderSegment.toString());

        for (AdditionalHeaderSegment ahs : additionalHeaderSegments) {
            sb.append(ahs.toString());
        }

        return sb.toString();
    }

    // --------------------------------------------------------------------------
    /** {@inheritDoc} */
    @Override
    public final boolean equals (Object o) {
        if (o instanceof ProtocolDataUnit == false) return false;

        ProtocolDataUnit oPdu = (ProtocolDataUnit) o;

        Iterator<AdditionalHeaderSegment> ahs1 = oPdu.getAdditionalHeaderSegments();
        Iterator<AdditionalHeaderSegment> ahs2 = this.getAdditionalHeaderSegments();

        while (ahs1.hasNext()) {
            if (!ahs1.equals(ahs2)) return false;
            ahs1.next();
            ahs2.next();
        }

        if (oPdu.getBasicHeaderSegment().equals(this.getBasicHeaderSegment()) && oPdu.getDataDigest().equals(this.getDataDigest()) && oPdu.getHeaderDigest().equals(this.getHeaderDigest()) && oPdu.getDataSegment().equals(this.getDataSegment())) return true;

        return false;
    }

    // --------------------------------------------------------------------------
    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (basicHeaderSegment != null ? basicHeaderSegment.hashCode() : 0);
        result = 31 * result + (additionalHeaderSegments != null ? additionalHeaderSegments.hashCode() : 0);
        result = 31 * result + (dataSegment != null ? dataSegment.hashCode() : 0);
        result = 31 * result + (headerDigest != null ? headerDigest.hashCode() : 0);
        result = 31 * result + (dataDigest != null ? dataDigest.hashCode() : 0);
        return result;
    }

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------

    /**
     * Calculates the needed size (in bytes) of serializing this object.
     * 
     * @return The needed size to store this object.
     */
    private final int calcSize(boolean includeDataSegment) {
        int size = BasicHeaderSegment.BHS_FIXED_SIZE;
        size += basicHeaderSegment.getTotalAHSLength() * AdditionalHeaderSegment.AHS_FACTOR;

        // plus the sizes of the used digests
        size += headerDigest.getSize();

	    if (includeDataSegment) {
	        size += AbstractDataSegment.getTotalLength(basicHeaderSegment.getDataSegmentLength());
	        size += dataDigest.getSize();
	    }

        return size;
    }

    private boolean calculateDigest(final ByteBuffer pdu, int offset, int length, IDigest digest) {
        if (digest.getSize() > 0) {
            digest.reset();
            pdu.mark();
            digest.update(pdu, offset, length);
            pdu.reset();
            
            return true;
        }
        
        return false;
    }

    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------
    // --------------------------------------------------------------------------
}
