/*--

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.


Module Name:

    kbfiltr.c

Abstract: This is an upper device filter driver sample for PS/2 keyboard. This
        driver layers in between the KbdClass driver and i8042prt driver and
        hooks the callback routine that moves keyboard inputs from the port
        driver to class driver. With this filter, you can remove or insert
        additional keys into the stream. This sample also creates a raw
        PDO and registers an interface so that application can talk to
        the filter driver directly without going thru the PS/2 devicestack.
        The reason for providing this additional interface is because the keyboard
        device is an exclusive secure device and it's not possible to open the
        device from usermode and send custom ioctls.

        If you want to filter keyboard inputs from all the keyboards (ps2, usb)
        plugged into the system then you can install this driver as a class filter
        and make it sit below the kbdclass filter driver by adding the service
        name of this filter driver before the kbdclass filter in the registry at
        " HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\
        {4D36E96B-E325-11CE-BFC1-08002BE10318}\UpperFilters"


Environment:

    Kernel mode only.

--*/

// #define __I8042_HOOK

#include "kbfiltr.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KbFilter_EvtDeviceAdd)
#pragma alloc_text (PAGE, KbFilter_EvtIoInternalDeviceControl)
#endif

ULONG InstanceNo = 0;

// the count of input datas we can hold one time
#define INPUTDATABUFFER_UNITCOUNT 128
// the maximum input data we can process one time
#define INPUTDATABUFFER_UNITCOUNT_ACCEPT 112
#define INPUTDATABUFFER_SIZE INPUTDATABUFFER_UNITCOUNT * sizeof(KEYBOARD_INPUT_DATA)
PKEYBOARD_INPUT_DATA g_InputDataPtr;

WDFMEMORY g_InputDataBufObject;

EVT_WDF_DRIVER_UNLOAD KbFilter_EvtDriverUnload;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Installable driver initialization entry point.
    This entry point is called directly by the I/O system.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG               config;
    NTSTATUS                        status;

    DebugPrint(("Keyboard Filter Driver Sample - Driver Framework Edition.\n"));
    DebugPrint(("Built %s %s\n", __DATE__, __TIME__));

	WdfMemoryCreate(WDF_NO_OBJECT_ATTRIBUTES, NonPagedPool, 
		KBFILTER_POOL_TAG,
		INPUTDATABUFFER_SIZE, &g_InputDataBufObject, &g_InputDataPtr);
    //
    // Initiialize driver config to control the attributes that
    // are global to the driver. Note that framework by default
    // provides a driver unload routine. If you create any resources
    // in the DriverEntry and want to be cleaned in driver unload,
    // you can override that by manually setting the EvtDriverUnload in the
    // config structure. In general xxx_CONFIG_INIT macros are provided to
    // initialize most commonly used members.
    //

    WDF_DRIVER_CONFIG_INIT(&config, KbFilter_EvtDeviceAdd);
	config.EvtDriverUnload = KbFilter_EvtDriverUnload;
	
    //
    // Create a framework driver object to represent our driver.
    //
    status = WdfDriverCreate(DriverObject, RegistryPath,
		WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE); // hDriver optional
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDriverCreate failed with status 0x%x\n", status));
    }

    return status;
}

VOID
KbFilter_EvtDriverUnload(
	IN WDFDRIVER Driver
	)
{
	UNREFERENCED_PARAMETER(Driver);

	WdfObjectDelete((WDFOBJECT)g_InputDataBufObject);
}


NTSTATUS
KbFilter_EvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. Here you can query the device properties
    using WdfFdoInitWdmGetPhysicalDevice/IoGetDeviceProperty and based
    on that, decide to create a filter device object and attach to the
    function stack.

    If you are not interested in filtering this particular instance of the
    device, you can just return STATUS_SUCCESS without creating a framework
    device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    NTSTATUS                status;
    WDFDEVICE               hDevice;
    WDFQUEUE                hQueue;
    PDEVICE_EXTENSION       filterExt;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    DebugPrint(("Enter FilterEvtDeviceAdd \n"));

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_KEYBOARD);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);

    //
    // Create a framework device object.  This call will in turn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &hDevice);
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n", status));
        return status;
    }

    filterExt = FilterGetData(hDevice);

    //
    // Configure the default queue to be Parallel. Do not use sequential queue
    // if this driver is going to be filtering PS2 ports because it can lead to
    // deadlock. The PS2 port driver sends a request to the top of the stack when it
    // receives an ioctl request and waits for it to be completed. If you use a
    // a sequential queue, this request will be stuck in the queue because of the 
    // outstanding ioctl request sent earlier to the port driver.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoInternalDeviceControl = KbFilter_EvtIoInternalDeviceControl;

	status = WdfIoQueueCreate(hDevice,
		&ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE); // pointer to default queue
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    //
    // Create a new queue to handle IOCTLs that will be forwarded to us from
    // the rawPDO. 
    //
    WDF_IO_QUEUE_CONFIG_INIT(&ioQueueConfig, WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoDeviceControl = KbFilter_EvtIoDeviceControlFromRawPdo;

    status = WdfIoQueueCreate(hDevice,
		&ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, &hQueue);
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    filterExt->rawPdoQueue = hQueue;

    //
    // Create a RAW pdo so we can provide a sideband communication with
    // the application. Please note that not filter drivers desire to
    // produce such a communication and not all of them are contrained
    // by other filter above which prevent communication thru the device
    // interface exposed by the main stack. So use this only if absolutely
    // needed. Also look at the toaster filter driver sample for an alternate
    // approach to providing sideband communication.
    //
	// I want control this device current.
    // status = KbFiltr_CreateRawPdo(hDevice, ++InstanceNo);

    return status;
}

VOID
KbFilter_EvtIoDeviceControlFromRawPdo(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for device control requests.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE hDevice;
    WDFMEMORY outputMemory;
    PDEVICE_EXTENSION devExt;
    size_t bytesTransferred = 0;

    UNREFERENCED_PARAMETER(InputBufferLength);

    DebugPrint(("Entered KbFilter_EvtIoDeviceControlFromRawPdo\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    //
    // Process the ioctl and complete it when you are done.
    //

    switch (IoControlCode) {
    case IOCTL_KBFILTR_GET_KEYBOARD_ATTRIBUTES:
        
        //
        // Buffer is too small, fail the request
        //
        if (OutputBufferLength < sizeof(KEYBOARD_ATTRIBUTES)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory);
        
        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed %x\n", status));
            break;
        }
        
        status = WdfMemoryCopyFromBuffer(outputMemory,
                                    0,
                                    &devExt->KeyboardAttributes,
                                    sizeof(KEYBOARD_ATTRIBUTES));

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfMemoryCopyFromBuffer failed %x\n", status));
            break;
        }

        bytesTransferred = sizeof(KEYBOARD_ATTRIBUTES);
        
        break;    
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    
    WdfRequestCompleteWithInformation(Request, status, bytesTransferred);

    return;
}

VOID
KbFilter_EvtIoInternalDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for internal device control requests.
    There are two specific control codes that are of interest:

    IOCTL_INTERNAL_KEYBOARD_CONNECT:
        Store the old context and function pointer and replace it with our own.
        This makes life much simpler than intercepting IRPs sent by the RIT and
        modifying them on the way back up.

    IOCTL_INTERNAL_I8042_HOOK_KEYBOARD:
        Add in the necessary function pointers and context values so that we can
        alter how the ps/2 keyboard is initialized.

    NOTE:  Handling IOCTL_INTERNAL_I8042_HOOK_KEYBOARD is *NOT* necessary if
           all you want to do is filter KEYBOARD_INPUT_DATAs.  You can remove
           the handling code and all related device extension fields and
           functions to conserve space.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    PDEVICE_EXTENSION               devExt;
#ifdef __I8042_HOOK
    PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
#endif
    PCONNECT_DATA                   connectData = NULL;
    NTSTATUS                        status = STATUS_SUCCESS;
    size_t                          length;
    WDFDEVICE                       hDevice;
    BOOLEAN                         forwardWithCompletionRoutine = FALSE;
    BOOLEAN                         ret = TRUE;
    WDFCONTEXT                      completionContext = WDF_NO_CONTEXT;
    WDF_REQUEST_SEND_OPTIONS        options;
    WDFMEMORY                       outputMemory;
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);


    PAGED_CODE();

    DebugPrint(("Entered KbFilter_EvtIoInternalDeviceControl\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    switch (IoControlCode) {

    //
    // Connect a keyboard class device driver to the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_CONNECT:
        //
        // Only allow one connection.
        //
        if (devExt->UpperConnectData.ClassService != NULL) {
            status = STATUS_SHARING_VIOLATION;
            break;
        }

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer).
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                                    sizeof(CONNECT_DATA),
                                    &connectData,
                                    &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        ASSERT(length == InputBufferLength);

        devExt->UpperConnectData = *connectData;

        //
        // Hook into the report chain.  Everytime a keyboard packet is reported
        // to the system, KbFilter_ServiceCallback will be called
        //

        connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);

#pragma warning(disable:4152)  //nonstandard extension, function/data pointer conversion

        connectData->ClassService = KbFilter_ServiceCallback;

#pragma warning(default:4152)

        break;

    //
    // Disconnect a keyboard class device driver from the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:

        //
        // Clear the connection parameters in the device extension.
        //
        // devExt->UpperConnectData.ClassDeviceObject = NULL;
        // devExt->UpperConnectData.ClassService = NULL;

        status = STATUS_NOT_IMPLEMENTED;
        break;

    //
    // Attach this driver to the initialization and byte processing of the
    // i8042 (ie PS/2) keyboard.  This is only necessary if you want to do PS/2
    // specific functions, otherwise hooking the CONNECT_DATA is sufficient
    //
    case IOCTL_INTERNAL_I8042_HOOK_KEYBOARD:
#ifdef __I8042_HOOK
        DebugPrint(("hook keyboard received!\n"));

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer)
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                            sizeof(INTERNAL_I8042_HOOK_KEYBOARD),
                            &hookKeyboard,
                            &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        ASSERT(length == InputBufferLength);

        //
        // Enter our own initialization routine and record any Init routine
        // that may be above us.  Repeat for the isr hook
        //
        devExt->UpperContext = hookKeyboard->Context;

        //
        // replace old Context with our own
        //
        hookKeyboard->Context = (PVOID) devExt;

        if (hookKeyboard->InitializationRoutine) {
            devExt->UpperInitializationRoutine =
                hookKeyboard->InitializationRoutine;
        }
        hookKeyboard->InitializationRoutine =
            (PI8042_KEYBOARD_INITIALIZATION_ROUTINE)
            KbFilter_InitializationRoutine;

        if (hookKeyboard->IsrRoutine) {
            devExt->UpperIsrHook = hookKeyboard->IsrRoutine;
        }
        hookKeyboard->IsrRoutine = (PI8042_KEYBOARD_ISR) KbFilter_IsrHook;

        //
        // Store all of the other important stuff
        //
        devExt->IsrWritePort = hookKeyboard->IsrWritePort;
        devExt->QueueKeyboardPacket = hookKeyboard->QueueKeyboardPacket;
        devExt->CallContext = hookKeyboard->CallContext;

        status = STATUS_SUCCESS;
#endif
        break;


    case IOCTL_KEYBOARD_QUERY_ATTRIBUTES:
        forwardWithCompletionRoutine = TRUE;
        completionContext = devExt;
        break;
        
    //
    // Might want to capture these in the future.  For now, then pass them down
    // the stack.  These queries must be successful for the RIT to communicate
    // with the keyboard.
    //
    case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
    case IOCTL_KEYBOARD_QUERY_INDICATORS:
    case IOCTL_KEYBOARD_SET_INDICATORS:
    case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
    case IOCTL_KEYBOARD_SET_TYPEMATIC:
        break;
    }

    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    //
    // Forward the request down. WdfDeviceGetIoTarget returns
    // the default target, which represents the device attached to us below in
    // the stack.
    //

    if (forwardWithCompletionRoutine) {

        //
        // Format the request with the output memory so the completion routine
        // can access the return data in order to cache it into the context area
        //
        
        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory); 

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        status = WdfIoTargetFormatRequestForInternalIoctl(WdfDeviceGetIoTarget(hDevice),
                                                         Request,
                                                         IoControlCode,
                                                         NULL,
                                                         NULL,
                                                         outputMemory,
                                                         NULL);

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfIoTargetFormatRequestForInternalIoctl failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }
    
        // 
        // Set our completion routine with a context area that we will save
        // the output data into
        //
        WdfRequestSetCompletionRoutine(Request,
                                    KbFilterRequestCompletionRoutine,
                                    completionContext);

        ret = WdfRequestSend(Request,
                             WdfDeviceGetIoTarget(hDevice),
                             WDF_NO_SEND_OPTIONS);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint( ("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }

    }
    else
    {

        //
        // We are not interested in post processing the IRP so 
        // fire and forget.
        //
        WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                      WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

        ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }
        
    }

    return;
}

NTSTATUS
KbFilter_InitializationRoutine(
    IN PVOID                           InitializationContext,
    IN PVOID                           SynchFuncContext,
    IN PI8042_SYNCH_READ_PORT          ReadPort,
    IN PI8042_SYNCH_WRITE_PORT         WritePort,
    OUT PBOOLEAN                       TurnTranslationOn
    )
/*++

Routine Description:

    This routine gets called after the following has been performed on the kb
    1)  a reset
    2)  set the typematic
    3)  set the LEDs

    i8042prt specific code, if you are writing a packet only filter driver, you
    can remove this function

Arguments:

    DeviceObject - Context passed during IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

    SynchFuncContext - Context to pass when calling Read/WritePort

    Read/WritePort - Functions to synchronoulsy read and write to the kb

    TurnTranslationOn - If TRUE when this function returns, i8042prt will not
                        turn on translation on the keyboard

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION  devExt;
    NTSTATUS            status = STATUS_SUCCESS;

    devExt = (PDEVICE_EXTENSION)InitializationContext;

    //
    // Do any interesting processing here.  We just call any other drivers
    // in the chain if they exist.  Make sure Translation is turned on as well
    //
    if (devExt->UpperInitializationRoutine) {
        status = (*devExt->UpperInitializationRoutine) (
                        devExt->UpperContext,
                        SynchFuncContext,
                        ReadPort,
                        WritePort,
                        TurnTranslationOn
                        );

        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    *TurnTranslationOn = TRUE;
    return status;
}

BOOLEAN
KbFilter_IsrHook(
    PVOID                  IsrContext,
    PKEYBOARD_INPUT_DATA   CurrentInput,
    POUTPUT_PACKET         CurrentOutput,
    UCHAR                  StatusByte,
    PUCHAR                 DataByte,
    PBOOLEAN               ContinueProcessing,
    PKEYBOARD_SCAN_STATE   ScanState
    )
/*++

Routine Description:

    This routine gets called at the beginning of processing of the kb interrupt.

    i8042prt specific code, if you are writing a packet only filter driver, you
    can remove this function

Arguments:

    DeviceObject - Our context passed during IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

    CurrentInput - Current input packet being formulated by processing all the
                    interrupts

    CurrentOutput - Current list of bytes being written to the keyboard or the
                    i8042 port.

    StatusByte    - Byte read from I/O port 60 when the interrupt occurred

    DataByte      - Byte read from I/O port 64 when the interrupt occurred.
                    This value can be modified and i8042prt will use this value
                    if ContinueProcessing is TRUE

    ContinueProcessing - If TRUE, i8042prt will proceed with normal processing of
                         the interrupt.  If FALSE, i8042prt will return from the
                         interrupt after this function returns.  Also, if FALSE,
                         it is this functions responsibilityt to report the input
                         packet via the function provided in the hook IOCTL or via
                         queueing a DPC within this driver and calling the
                         service callback function acquired from the connect IOCTL

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION devExt;
    BOOLEAN           retVal = TRUE;

    devExt = (PDEVICE_EXTENSION)IsrContext;

	DebugPrintEx("Entered KbFilter_IsrHook\n");

	if (devExt->UpperIsrHook) {
        retVal = (*devExt->UpperIsrHook) (
                        devExt->UpperContext,
                        CurrentInput,
                        CurrentOutput,
                        StatusByte,
                        DataByte,
                        ContinueProcessing,
                        ScanState
                        );

        if (!retVal || !(*ContinueProcessing)) {
            return retVal;
        }
    }

    *ContinueProcessing = TRUE;
    return retVal;
}

__inline ULONG is_same_makekey(PKEYBOARD_INPUT_DATA Input, USHORT MakeCode, USHORT Flags)
{
	return (Input->MakeCode == MakeCode) && ((Input->Flags & 0xF) == Flags);
}

__inline ULONG is_same_breakkey(PKEYBOARD_INPUT_DATA Input, USHORT MakeCode, USHORT Flags)
{
	return (Input->MakeCode == MakeCode) && ((Input->Flags & 0xF) == Flags);
}

__inline void copy_and_set_keycode(PKEYBOARD_INPUT_DATA target, PKEYBOARD_INPUT_DATA source, USHORT makecode, ULONG flags)
{
	memset(target, 0, sizeof(KEYBOARD_INPUT_DATA));
	target->UnitId = source->UnitId;
	target->MakeCode = makecode ? makecode : source->MakeCode;
	target->Flags = (flags & 0xFFFF0000) ? (USHORT)(flags>>16) : source->Flags;
}

__inline void set_keycode(PKEYBOARD_INPUT_DATA target, USHORT id, USHORT makecode, USHORT flags)
{
	memset(target, 0, sizeof(KEYBOARD_INPUT_DATA));
	target->UnitId = id;
	target->MakeCode = makecode;
	target->Flags = flags;
}

VOID
KbFilter_ServiceCallback1(
IN PDEVICE_OBJECT  DeviceObject,
IN PKEYBOARD_INPUT_DATA InputDataStart,
IN PKEYBOARD_INPUT_DATA InputDataEnd,
IN OUT PULONG InputDataConsumed
)
{
	PDEVICE_EXTENSION   devExt;
	WDFDEVICE   hDevice;
	PKEYBOARD_INPUT_DATA ptr, gptr;

	gptr = g_InputDataPtr;

	hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

	devExt = FilterGetData(hDevice);

	DebugPrintEx("%u { ", InputDataEnd - InputDataStart);
	for (ptr = InputDataStart; ptr != InputDataEnd; ptr++)
	{
	
		DebugPrintEx("%c%s%s%X%c",
			ptr->Flags & KEY_BREAK ? '(' : '[',
			ptr->Flags & KEY_E0 ? "E0_" : "",
			ptr->Flags & KEY_E1 ? "E1_" : "",
			ptr->MakeCode,
			ptr->Flags & KEY_BREAK ? ')' : ']');
	}
	DebugPrintEx(" }\n");

	(*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
		devExt->UpperConnectData.ClassDeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);
}


VOID
KbFilter_ServiceCallback(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PKEYBOARD_INPUT_DATA InputDataStart,
    IN PKEYBOARD_INPUT_DATA InputDataEnd,
    IN OUT PULONG InputDataConsumed
    )
/*++

Routine Description:

    Called when there are keyboard packets to report to the Win32 subsystem.
    You can do anything you like to the packets.  For instance:

    o Drop a packet altogether
    o Mutate the contents of a packet
    o Insert packets into the stream

Arguments:

    DeviceObject - Context passed during the connect IOCTL

    InputDataStart - First packet to be reported

    InputDataEnd - One past the last packet to be reported.  Total number of
                   packets is equal to InputDataEnd - InputDataStart

    InputDataConsumed - Set to the total number of packets consumed by the RIT
                        (via the function pointer we replaced in the connect
                        IOCTL)

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION   devExt;
    WDFDEVICE   hDevice;
	PKEYBOARD_INPUT_DATA ptr, gptr;

	gptr = g_InputDataPtr;

    hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

    devExt = FilterGetData(hDevice);

	if (InputDataEnd - InputDataStart > INPUTDATABUFFER_UNITCOUNT_ACCEPT)
	{
		DebugPrintEx("Too many keyboard input, just pass through\n");

		(*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
			devExt->UpperConnectData.ClassDeviceObject, InputDataStart, InputDataEnd, InputDataConsumed);

		return;
	}
		
	DebugPrintEx("%u { ", InputDataEnd - InputDataStart);
	for (ptr = InputDataStart; ptr != InputDataEnd; ptr++)
	{
		// ignore E02A, E036, E0AA, E0B6 
		// that will make 
		// 1. Home, End, Insert, Delete, PageUp, PageDown
		//	  generate same Make/Break code regardless NumLock state
		// 2. / generate same Make/Break code despite modify keys
		// 3. PrintSc become single byte key
		if (ptr->Flags & KEY_E0) {
			if (ptr->MakeCode == 0x2A ||
				ptr->MakeCode == 0x36 ||
				ptr->MakeCode == 0xAA ||
				ptr->MakeCode == 0xB6)
				continue;
		}

#define SKIP_MAKECODE(code, flags, modifykey) \
	if (is_same_makekey(ptr, code, flags)) { \
		/* if(g_ModifykeyState.##modifykey) continue; \
		else */g_ModifykeyState.##modifykey = 0xF; \
	}
#define SKIP_BREAKCODE(code, flags, modifykey) \
	if (is_same_breakkey(ptr, code, flags)) { \
		if(g_ModifykeyState.##modifykey) g_ModifykeyState.##modifykey = 0; \
		/*else continue;*/ \
	}

		SKIP_MAKECODE(0x5B, KEY_MAKE | KEY_E0, Windows.Left)
		else SKIP_MAKECODE(0x5C, KEY_MAKE | KEY_E0, Windows.Right)
		else SKIP_MAKECODE(0x2A, KEY_MAKE, Shift.Left)
		else SKIP_MAKECODE(0x36, KEY_MAKE, Shift.Right)
		else SKIP_MAKECODE(0x1D, KEY_MAKE, Control.Left)
		else SKIP_MAKECODE(0x1D, KEY_MAKE | KEY_E0, Control.Right)
		else SKIP_MAKECODE(0x38, KEY_MAKE, Alt.Left)
		else SKIP_MAKECODE(0x38, KEY_MAKE | KEY_E0, Alt.Right)

		SKIP_BREAKCODE(0x5B, KEY_BREAK | KEY_E0, Windows.Left)
		else SKIP_BREAKCODE(0x5C, KEY_BREAK | KEY_E0, Windows.Right)
		else SKIP_BREAKCODE(0x2A, KEY_BREAK, Shift.Left)
		else SKIP_BREAKCODE(0x36, KEY_BREAK, Shift.Right)
		else SKIP_BREAKCODE(0x1D, KEY_BREAK, Control.Left)
		else SKIP_BREAKCODE(0x1D, KEY_BREAK | KEY_E0, Control.Right)
		else SKIP_BREAKCODE(0x38, KEY_BREAK, Alt.Left)
		else SKIP_BREAKCODE(0x38, KEY_BREAK | KEY_E0, Alt.Right)

#undef SKIP_MAKECODE
#undef SKIP_BREAKCODE

		// map PrtSc to Application
		if (is_same_makekey(ptr, 0x37, KEY_MAKE | KEY_E0) ||
			is_same_makekey(ptr, 0x54, KEY_MAKE | KEY_E0)) // Alt + PrtSc
		{
			// skip
		}
		else if (is_same_breakkey(ptr, 0x37, KEY_BREAK | KEY_E0) ||
			is_same_breakkey(ptr, 0x54, KEY_BREAK | KEY_E0)) // Alt + PrtSc
		{
			set_keycode(gptr++, ptr->UnitId, 0x5D, KEY_MAKE | KEY_E0);
			set_keycode(gptr++, ptr->UnitId, 0x5D, KEY_BREAK | KEY_E0);
		}
		// map ScanNextTrack (E019) to PrintSc (E02A E037)
		else if (is_same_makekey(ptr, 0x19, KEY_MAKE | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x2A, KEY_MAKE | KEY_E0);
			set_keycode(gptr++, ptr->UnitId, 0x37, KEY_MAKE | KEY_E0);
		}
		else if (is_same_breakkey(ptr, 0x19, KEY_BREAK | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x37, KEY_BREAK | KEY_E0);
			set_keycode(gptr++, ptr->UnitId, 0x2A, KEY_BREAK | KEY_E0);
		}
		// map PlayPause (E022) to Pause/Break (E11D 45 E19D C5)
		else if (is_same_makekey(ptr, 0x22, KEY_MAKE | KEY_E0))
		{
			// skip
		}
		else if (is_same_breakkey(ptr, 0x22, KEY_BREAK | KEY_E0))
		{
			if (g_ModifykeyState.Control.VALUE) // Ctrl + Break (E046 E0C6)
			{
				set_keycode(gptr++, ptr->UnitId, 0x46, KEY_MAKE | KEY_E0);
				set_keycode(gptr++, ptr->UnitId, 0xC6, KEY_MAKE | KEY_E0);
				g_ModifykeyState.InPauseBreak = 1;
			}
			else
			{
				set_keycode(gptr++, ptr->UnitId, 0x1D, KEY_MAKE | KEY_E1);
				set_keycode(gptr++, ptr->UnitId, 0x45, KEY_MAKE);
				set_keycode(gptr++, ptr->UnitId, 0x9D, KEY_MAKE | KEY_E1);
				set_keycode(gptr++, ptr->UnitId, 0xC5, KEY_MAKE);
				g_ModifykeyState.InPauseBreak = 1;
			}
		}
		// map ScanPreviousTrack (E010) to VK_F20(6B)
		else if (is_same_makekey(ptr, 0x10, KEY_MAKE | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6B, KEY_MAKE);
		}
		else if (is_same_breakkey(ptr, 0x10, KEY_BREAK | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6B, KEY_BREAK);
		}
		// swap Home (E047) with PageUp (E049)
		else if (is_same_makekey(ptr, 0x47, KEY_MAKE | KEY_E0)) // Home
		{
			set_keycode(gptr++, ptr->UnitId, 0x49, KEY_MAKE | KEY_E0);
		}
		else if (is_same_breakkey(ptr, 0x47, KEY_BREAK | KEY_E0)) // Home
		{
			set_keycode(gptr++, ptr->UnitId, 0x49, KEY_BREAK | KEY_E0);
		}
		else if (is_same_makekey(ptr, 0x49, KEY_MAKE | KEY_E0)) // PageUp
		{
			set_keycode(gptr++, ptr->UnitId, 0x47, KEY_MAKE | KEY_E0);
		}
		else if (is_same_breakkey(ptr, 0x49, KEY_BREAK | KEY_E0)) // PageUp
		{
			set_keycode(gptr++, ptr->UnitId, 0x47, KEY_BREAK | KEY_E0);
		}
		// swap End (E04F) with PageDown (E051)
		else if (is_same_makekey(ptr, 0x4F, KEY_MAKE | KEY_E0)) // End
		{
			set_keycode(gptr++, ptr->UnitId, 0x51, KEY_MAKE | KEY_E0);
		}
		else if (is_same_breakkey(ptr, 0x4F, KEY_BREAK | KEY_E0)) // End
		{
			set_keycode(gptr++, ptr->UnitId, 0x51, KEY_BREAK | KEY_E0);
		}
		else if (is_same_makekey(ptr, 0x51, KEY_MAKE | KEY_E0)) // PageDown
		{
			set_keycode(gptr++, ptr->UnitId, 0x4F, KEY_MAKE | KEY_E0);
		}
		else if (is_same_breakkey(ptr, 0x51, KEY_BREAK | KEY_E0)) // PageDown
		{
			set_keycode(gptr++, ptr->UnitId, 0x4F, KEY_BREAK | KEY_E0);
		}
		// disable Win + L (lock) and map to VK_F24(76)
		else if (is_same_makekey(ptr, 0x26, KEY_MAKE))
		{
			if (g_ModifykeyState.Windows.VALUE)
				set_keycode(gptr++, ptr->UnitId, 0x76, KEY_MAKE);
			else
				copy_and_set_keycode(gptr++, ptr, 0, 0);
		}
		else if (is_same_breakkey(ptr, 0x26, KEY_BREAK))
		{

			if (g_ModifykeyState.Windows.VALUE)
				set_keycode(gptr++, ptr->UnitId, 0x76, KEY_BREAK);
			else
				copy_and_set_keycode(gptr++, ptr, 0, 0);
		}
		// map Calc (E021) to VK_F21(6C)
		else if (is_same_makekey(ptr, 0x21, KEY_MAKE | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6C, KEY_MAKE);
		}
		else if (is_same_makekey(ptr, 0x21, KEY_BREAK | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6C, KEY_BREAK);
		}
		// map Search (E065) to VK_F22(E06D)
		else if (is_same_makekey(ptr, 0x65, KEY_MAKE | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6D, KEY_MAKE);
		}
		else if (is_same_makekey(ptr, 0x65, KEY_BREAK | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6D, KEY_BREAK);
		}
		// map Explorer (E06B) to VK_F23(E06E)
		else if (is_same_makekey(ptr, 0x6B, KEY_MAKE | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6E, KEY_MAKE);
		}
		else if (is_same_makekey(ptr, 0x6B, KEY_BREAK | KEY_E0))
		{
			set_keycode(gptr++, ptr->UnitId, 0x6E, KEY_BREAK);
		}
		// anything else, keep
		else
		{
			copy_and_set_keycode(gptr++, ptr, 0, 0);
		}
			
		DebugPrintEx("%c%s%s%X%c",
			(gptr-1)->Flags & KEY_BREAK ? '(' : '[',
			(gptr-1)->Flags & KEY_E0 ? "E0_" : "",
			(gptr-1)->Flags & KEY_E1 ? "E1_" : "",
			(gptr-1)->MakeCode,
			(gptr-1)->Flags & KEY_BREAK ? ')' : ']');
	}
	DebugPrintEx(" }\n");

	set_keycode(gptr, 0, 0, 0);
	
	(*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
		devExt->UpperConnectData.ClassDeviceObject, g_InputDataPtr, gptr, InputDataConsumed);
	if ((*InputDataConsumed) == (gptr - g_InputDataPtr))
		(*InputDataConsumed) = (ULONG)(InputDataEnd - InputDataStart);
	else if ((*InputDataConsumed) > (InputDataEnd - InputDataStart))
		(*InputDataConsumed) = (ULONG)(InputDataEnd - InputDataStart);
}


VOID
KbFilterRequestCompletionRoutine(
    WDFREQUEST                  Request,
    WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    WDFCONTEXT                  Context
   )
/*++

Routine Description:

    Completion Routine

Arguments:

    Target - Target handle
    Request - Request handle
    Params - request completion params
    Context - Driver supplied context


Return Value:

    VOID

--*/
{
    WDFMEMORY buffer = CompletionParams->Parameters.Ioctl.Output.Buffer;

    UNREFERENCED_PARAMETER(Target);
    //
    // Save the keyboard attributes in our context area so that we can return
    // them to the app later.
    //
    if (CompletionParams->Type == WdfRequestTypeDeviceControlInternal &&
        NT_SUCCESS(CompletionParams->IoStatus.Status) && 
        CompletionParams->Parameters.Ioctl.IoControlCode == IOCTL_KEYBOARD_QUERY_ATTRIBUTES) {

        if( CompletionParams->Parameters.Ioctl.Output.Length >= sizeof(KEYBOARD_ATTRIBUTES)) {
            WdfMemoryCopyToBuffer(buffer,
                                  CompletionParams->Parameters.Ioctl.Output.Offset,
                                  &((PDEVICE_EXTENSION)Context)->KeyboardAttributes,
                                  sizeof(KEYBOARD_ATTRIBUTES)
                                  );
        }
    }

    WdfRequestComplete(Request, CompletionParams->IoStatus.Status);

    return;
}
