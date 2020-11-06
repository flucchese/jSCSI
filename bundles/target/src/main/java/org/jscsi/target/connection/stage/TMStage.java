package org.jscsi.target.connection.stage;


import java.io.IOException;
import java.security.DigestException;

import org.jscsi.exception.InternetSCSIException;
import org.jscsi.parser.BasicHeaderSegment;
import org.jscsi.parser.ProtocolDataUnit;
import org.jscsi.parser.tmf.TaskManagementFunctionRequestParser;
import org.jscsi.parser.tmf.TaskManagementFunctionResponseParser;
import org.jscsi.parser.tmf.TaskManagementFunctionResponseParser.ResponseCode;
import org.jscsi.target.connection.TargetPduFactory;
import org.jscsi.target.connection.phase.TargetFullFeaturePhase;
import org.jscsi.target.connection.stage.fullfeature.TargetFullFeatureStage;
import org.jscsi.target.settings.SettingsException;
import org.apache.log4j.Logger;
import org.apache.log4j.LogManager;


/**
 * A stage for processing Task Management Function Request defined in RFC(7320).
 * 
 * Warning, this class is only a dummy to react on the request without functionality except for response.
 * 
 * @author Andreas Rain
 */
public class TMStage extends TargetFullFeatureStage {

    private static final Logger log = LogManager.getLogger(TMStage.class);

    /**
     * @param targetFullFeaturePhase
     */
    public TMStage (TargetFullFeaturePhase targetFullFeaturePhase) {
        super(targetFullFeaturePhase);
    }

    @Override
    public ProtocolDataUnit execute (ProtocolDataUnit pdu) throws IOException , InterruptedException , InternetSCSIException , DigestException , SettingsException {

        final BasicHeaderSegment bhs = pdu.getBasicHeaderSegment();
        final TaskManagementFunctionRequestParser parser = (TaskManagementFunctionRequestParser) bhs.getParser();
        final int initiatorTaskTag = bhs.getInitiatorTaskTag();

        TaskManagementFunctionResponseParser.ResponseCode responseCode = ResponseCode.TASK_DOES_NOT_EXIST;

        switch (parser.getFunction()) {
            case ABORT_TASK :
                log.error("ABORT_TASK");
                break;
            case ABORT_TASK_SET :
                log.error("ABORT_TASK_SET");
                break;
            case CLEAR_ACA :
                responseCode = ResponseCode.FUNCTION_COMPLETE;
                break;
            case CLEAR_TASK_SET :
                responseCode = ResponseCode.FUNCTION_COMPLETE;
                break;
            case LUN_RESET :
                log.error("LUN_RESET");
                break;
            case TARGET_WARM_RESET :
                log.error("TARGET_WARM_RESET");
                break;
            case TARGET_COLD_RESET :
                log.error("TARGET_COLD_RESET");
                break;
            case TASK_REASSIGN :
                log.error("TASK_REASSIGN");
                break;
            default :
                break;
        }

        final ProtocolDataUnit responsePDU = TargetPduFactory.createTMResponsePdu(responseCode, initiatorTaskTag);
        connection.sendPdu(responsePDU);

        return null;
    }

}
