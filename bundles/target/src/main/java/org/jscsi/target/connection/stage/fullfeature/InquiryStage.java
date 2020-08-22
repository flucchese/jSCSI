package org.jscsi.target.connection.stage.fullfeature;


import java.io.IOException;
import java.security.DigestException;

import org.jscsi.exception.InternetSCSIException;
import org.jscsi.parser.BasicHeaderSegment;
import org.jscsi.parser.ProtocolDataUnit;
import org.jscsi.parser.scsi.SCSICommandParser;
import org.jscsi.target.connection.phase.TargetFullFeaturePhase;
import org.jscsi.target.scsi.IResponseData;
import org.jscsi.target.scsi.cdb.InquiryCDB;
import org.jscsi.target.scsi.inquiry.PageCode.VitalProductDataPageName;
import org.jscsi.target.scsi.inquiry.StandardInquiryData;
import org.jscsi.target.scsi.inquiry.SupportedVpdPages;
import org.jscsi.target.scsi.sense.senseDataDescriptor.senseKeySpecific.FieldPointerSenseKeySpecificData;
import org.jscsi.target.settings.SettingsException;
import org.jscsi.target.util.Debug;
import org.apache.log4j.Logger;
import org.apache.log4j.LogManager;


/**
 * A stage for processing <code>INQUIRY</code> SCSI commands.
 * 
 * @author Andreas Ergenzinger
 */
public class InquiryStage extends TargetFullFeatureStage {

    private static final Logger log = LogManager.getLogger(InquiryStage.class);

    public InquiryStage (TargetFullFeaturePhase targetFullFeaturePhase) {
        super(targetFullFeaturePhase);
    }

    @Override
    public void execute (ProtocolDataUnit pdu) throws IOException , InterruptedException , InternetSCSIException , DigestException , SettingsException {

        final BasicHeaderSegment bhs = pdu.getBasicHeaderSegment();
        final SCSICommandParser parser = (SCSICommandParser) bhs.getParser();

        ProtocolDataUnit responsePdu;// the response PDU

        // get command details in CDB
        log.debug("CDB bytes: \n" + Debug.byteBufferToString(parser.getCDB()));

        final InquiryCDB cdb = new InquiryCDB(parser.getCDB());
        final FieldPointerSenseKeySpecificData[] illegalFieldPointers = cdb.getIllegalFieldPointers();

        log.debug("cdb.getAllocationLength() = " + cdb.getAllocationLength());
        log.debug("cdb.getEnableVitalProductData() = " + cdb.getEnableVitalProductData());
        log.debug("cdb.isNormalACA() = " + cdb.isNormalACA());
        log.debug("cdb.getPageCode() = " + cdb.getPageCode());
        log.debug("cdb.getPageCode().getVitalProductDataPageName() = " + cdb.getPageCode().getVitalProductDataPageName());

        if (illegalFieldPointers != null) {
            // an illegal request has been made
            log.error("illegal INQUIRY request");

            responsePdu = createFixedFormatErrorPdu(illegalFieldPointers, bhs.getInitiatorTaskTag(), parser.getExpectedDataTransferLength());

            // send response
            connection.sendPdu(responsePdu);

        } else {
            // PDU is okay
            // carry out command

            IResponseData responseData;

            // "If the EVPD bit is set to zero, ...
            if (!cdb.getEnableVitalProductData()) {
                // ... the device server shall return the standard INQUIRY
                // data."
                responseData = StandardInquiryData.getInstance();
            } else {
                /*
                 * SCSI initiator is requesting either "device identification" or "supported VPD pages" or this else
                 * block would not have been entered. (see {@link InquiryCDB#checkIntegrity(ByteBuffer dataSegment)})
                 */
                final VitalProductDataPageName pageName = cdb.getPageCode().getVitalProductDataPageName();

                switch (pageName) {// is never null
                    case SUPPORTED_VPD_PAGES :
                        responseData = SupportedVpdPages.getInstance();
                        break;
                    case DEVICE_IDENTIFICATION :
                        responseData = session.getTargetServer().getDeviceIdentificationVpdPage();
                        break;
                    default :
                        // The initiator must not request unsupported mode pages.
                        throw new InternetSCSIException();
                }
            }

            // send response
            sendResponse(bhs.getInitiatorTaskTag(), parser.getExpectedDataTransferLength(), responseData);
           
        }

    }

}
