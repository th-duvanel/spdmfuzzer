/**
@file
UEFI OS based application.

Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "SpdmRequesterTest.h"

extern VOID          *mSpdmContext;

/**
  This function executes SPDM measurement and extend to TPM.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
SpdmSendReceiveGetMeasurement (
  IN VOID          *SpdmContext
  )
{
  RETURN_STATUS                             Status;
  UINT8                                     NumberOfBlocks;
  UINT8                                     NumberOfBlock;
  UINT32                                    MeasurementRecordLength;
  UINT8                                     MeasurementRecord[MAX_SPDM_MEASUREMENT_RECORD_SIZE];
  UINT8                                     Index;
  UINT8                                     RequestAttribute;

  RequestAttribute = 0;
  //
  // 1. Query the total number of measurements available.
  //
  Status = SpdmGetMeasurement (
             SpdmContext,
             RequestAttribute,
             SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTOAL_NUMBER_OF_MEASUREMENTS,
             0,
             &NumberOfBlocks,
             NULL,
             NULL
             );
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  DEBUG((DEBUG_INFO, "NumberOfBlocks - 0x%x\n", NumberOfBlocks));
  for (Index = 1; Index <= NumberOfBlocks; Index++) {
    DEBUG((DEBUG_INFO, "Index - 0x%x\n", Index));
    //
    // 2. query measurement one by one
    // get signature in last message only.
    //
    if (Index == NumberOfBlocks) {
      RequestAttribute = SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
    }
    MeasurementRecordLength = sizeof(MeasurementRecord);
    Status = SpdmGetMeasurement (
              SpdmContext,
              RequestAttribute,
              Index,
              0,
              &NumberOfBlock,
              &MeasurementRecordLength,
              MeasurementRecord
              );
    if (RETURN_ERROR(Status)) {
      return Status;
    }
  }

  return RETURN_SUCCESS;
}

/**
  This function executes SPDM measurement and extend to TPM.
  
  @param[in]  SpdmContext            The SPDM context for the device.
  @param[out] DeviceSecurityState    The Device Security state associated with the device.
**/
RETURN_STATUS
DoMeasurementViaSpdm (
  VOID
  )
{
  RETURN_STATUS         Status;
  VOID                  *SpdmContext;

  SpdmContext = mSpdmContext;
  
  Status = SpdmSendReceiveGetMeasurement (SpdmContext);
  if (RETURN_ERROR(Status)) {
    return Status;
  }
  return RETURN_SUCCESS;
}
