//! Durable privileged mutation admission; uncertain effects never produce terminal proof.
use crate::journal::{Admission, Journal};
use std::io;
use wolf_core::*;
pub fn serve(
    journal: &Journal,
    pc: &PcId,
    request: &RpcRequest,
    action: impl FnOnce(&RpcOperation) -> Result<RpcResult, SafeError>,
) -> io::Result<RpcResponse> {
    request
        .validate_pc(pc)
        .map_err(|_| io::Error::other("invalid RPC authority"))?;
    let ticket = if matches!(
        request.operation,
        RpcOperation::ApplySettings(_)
            | RpcOperation::Start(_)
            | RpcOperation::Stop(_)
            | RpcOperation::Restart(_)
    ) {
        match journal.begin(request)? {
            Admission::Cached(response) => return Ok(response),
            Admission::Uncertain(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "RPC requires reconciliation",
                ));
            }
            Admission::Execute(mut ticket) => {
                ticket.running()?;
                Some(ticket)
            }
        }
    } else {
        None
    };
    let outcome = if let RpcOperation::RequestStatus(payload) = &request.operation {
        journal
            .lookup(payload.original_request_id, pc)
            .map(RpcResult::RequestStatus)
            .map_err(|_| SafeError::new("recovery_pending"))
    } else {
        action(&request.operation)
    };
    if outcome
        .as_ref()
        .is_err_and(|error| error.code() == ErrorCode::UnknownInterrupted)
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "RPC requires reconciliation",
        ));
    }
    let (result, error) = match outcome {
        Ok(result) => (Some(result), None),
        Err(error) => (None, Some(error)),
    };
    let response = RpcResponse {
        version: 1,
        request_id: request.request_id,
        pc_id: pc.clone(),
        ok: result.is_some(),
        result,
        error,
    };
    response
        .validate_for(request)
        .map_err(|_| io::Error::other("invalid RPC completion"))?;
    if let Some(ticket) = ticket {
        ticket.finish(response.clone())?;
    }
    Ok(response)
}
