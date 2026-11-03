// SPDX-License-Identifier: BSD-2-Clause-Patent
#include <Uefi.h>
#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiLib.h>
#include <Protocol/UniXNULoader.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/BlockIo.h>
#include <UkeMemStatus.h>
#include "BootArgs.h"
#include "BootVideo.h"
#include "PackedRamdisk.h"
#include "WindowSize.h"

#define WINDOW_SIZE  SIZE_256MB
#define BLOCK_SIZE   SIZE_2MB
#define MAX_SEGMENTS 64

typedef struct {
  UINT64  Address;
  UINT64  Size;
  UINT64  FileOffset;
  UINT64  FileSize;
  UINT32  Protection;
} SEGMENT;

typedef struct {
  SEGMENT  Segments[MAX_SEGMENTS];
  UINTN    Count;
  UINT64   Base;
  UINT64   End;
  UINT64   Entry;
} KERNEL;

STATIC EFI_HANDLE  mImage;
UINT64 EFIAPI DarwinCurrentEl (VOID);
VOID EFIAPI DarwinEnter (UINT64 Args, UINT64 Entry, UINT64 Memory, UINT64 Size, UINT64 VideoBase, UINT64 VideoBytes);

#define READ_SYSREG(Name)  ({ UINT64 Value_; __asm__ volatile ("mrs %0, " #Name : "=r" (Value_)); Value_; })

STATIC UINT32 U32 (CONST VOID *P) { return ReadUnaligned32 ((CONST UINT32 *)P); }
STATIC UINTN mAdtFailLine;
STATIC BOOLEAN AdtFail (UINTN Line) { mAdtFailLine = Line; return FALSE; }
STATIC UINT64 U64 (CONST VOID *P) { return ReadUnaligned64 ((CONST UINT64 *)P); }

STATIC
EFI_STATUS
ReadBootVideo (UINT64 Video[6])
{
  EFI_GRAPHICS_OUTPUT_PROTOCOL           *Gop;
  EFI_STATUS                            Status;

  ZeroMem (Video, 6 * sizeof (*Video));
  Status = gBS->HandleProtocol (gST->ConsoleOutHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)&Gop);
  if (EFI_ERROR (Status)) {
    Status = gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop);
  }
  if (Status == EFI_NOT_FOUND) { return EFI_SUCCESS; }
  if (EFI_ERROR (Status)) { return Status; }
  return DarwinBootVideoFromGop (Gop, Video);
}

STATIC
EFI_STATUS
ReadFile (
  EFI_FILE_PROTOCOL *Root,
  CONST CHAR16      *Path,
  UINTN             Limit,
  VOID              **Data,
  UINTN             *Size
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *File;
  EFI_FILE_INFO      *Info;
  UINTN              InfoSize;
  UINTN              Actual;

  *Data = NULL;
  *Size = 0;
  Status = Root->Open (Root, &File, (CHAR16 *)Path, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) { return Status; }
  Info = NULL;
  InfoSize = 0;
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &InfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) { goto Done; }
  Info = AllocatePool (InfoSize);
  if (Info == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &InfoSize, Info);
  if (EFI_ERROR (Status)) { goto Done; }
  if ((Info->Attribute & EFI_FILE_DIRECTORY) || (Info->FileSize == 0) || (Info->FileSize > Limit)) {
    Print (L"DARWINBOOT: %s attr %lx size %lu limit %lu\n", Path, (UINT64)Info->Attribute, (UINT64)Info->FileSize, (UINT64)Limit);
    Status = EFI_BAD_BUFFER_SIZE;
    goto Done;
  }
  *Size = (UINTN)Info->FileSize;
  /* Zeroed: a tail the FAT read never fills then reads as 0, not as leftover pool bytes. */
  *Data = AllocateZeroPool (*Size);
  if (*Data == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  /*
   * Bound individual FAT read requests and handle short reads. The earlier Uke tail-corruption
   * diagnosis was superseded by the ABL handoff / DXE heap overlap finding; the caller still
   * receives either the complete file or an explicit error.
   */
  {
    UINT8 *Cursor = (UINT8 *)*Data;
    UINTN Left = *Size;
    Status = EFI_SUCCESS;
    while (Left != 0) {
      Actual = Left > SIZE_64KB ? SIZE_64KB : Left;
      Status = File->Read (File, &Actual, Cursor);
      if (EFI_ERROR (Status) || (Actual == 0)) { break; }
      Cursor += Actual;
      Left -= Actual;
    }
    if (!EFI_ERROR (Status) && (Left != 0)) { Status = EFI_DEVICE_ERROR; }
  }
Done:
  if (Info != NULL) { FreePool (Info); }
  File->Close (File);
  if (EFI_ERROR (Status) && (*Data != NULL)) { FreePool (*Data); *Data = NULL; }
  return Status;
}

STATIC
EFI_STATUS
ParseKernelHeader (CONST UINT8 *Data, UINTN Size, UINTN Header, KERNEL *Kernel)
{
  UINTN    Offset;
  UINTN    End;
  UINTN    Index;
  UINTN    Other;
  UINT32   Count;
  UINT32   Command;
  UINT32   Length;
  SEGMENT  *Segment;
  BOOLEAN  HasEntry;
  BOOLEAN  Executable;

  if ((Header > Size) || (Size - Header < 32) ||
      (U32 (Data + Header) != 0xfeedfacf) || (U32 (Data + Header + 4) != 0x100000c) ||
      (((U32 (Data + Header + 8) & 0x00ffffff) != 0) &&
       ((U32 (Data + Header + 8) & 0x00ffffff) != 2)) ||
      ((U32 (Data + Header + 12) != 2) &&
       ((Header != 0) || (U32 (Data + Header + 12) != 12)))) {
    return EFI_UNSUPPORTED;
  }
  if (U32 (Data + Header + 20) > Size - Header - 32) { return EFI_LOAD_ERROR; }
  ZeroMem (Kernel, sizeof (*Kernel));
  Count = U32 (Data + Header + 16);
  End = Header + 32 + U32 (Data + Header + 20);
  Offset = Header + 32;
  HasEntry = FALSE;
  for (Index = 0; Index < Count; Index++) {
    if (End - Offset < 8) { return EFI_LOAD_ERROR; }
    Command = U32 (Data + Offset);
    Length = U32 (Data + Offset + 4);
    if ((Length < 8) || (Length & 7) || (Length > End - Offset)) { return EFI_LOAD_ERROR; }
    if (Command == 0x19) {
      if ((Length < 72) || (U32 (Data + Offset + 64) > (Length - 72) / 80) ||
          (Kernel->Count == MAX_SEGMENTS)) { return EFI_LOAD_ERROR; }
      if (U64 (Data + Offset + 32) != 0) {
        Segment = &Kernel->Segments[Kernel->Count++];
        Segment->Address = U64 (Data + Offset + 24);
        Segment->Size = U64 (Data + Offset + 32);
        Segment->FileOffset = U64 (Data + Offset + 40);
        Segment->FileSize = U64 (Data + Offset + 48);
        Segment->Protection = U32 (Data + Offset + 60);
        if ((Segment->Size > WINDOW_SIZE) || (Segment->Address > MAX_UINT64 - Segment->Size) ||
            (Segment->FileSize > Segment->Size) || (Segment->FileOffset > Size) ||
            (Segment->FileSize > Size - Segment->FileOffset)) { return EFI_LOAD_ERROR; }
      }
    } else if (Command == 5) {
      if (HasEntry || (Length != 288) || (U32 (Data + Offset + 8) != 6) ||
          (U32 (Data + Offset + 12) != 68)) { return EFI_LOAD_ERROR; }
      Kernel->Entry = U64 (Data + Offset + 272);
      HasEntry = TRUE;
    }
    Offset += Length;
  }
  if ((Offset != End) || !HasEntry || (Kernel->Count == 0)) { return EFI_LOAD_ERROR; }
  Kernel->Base = MAX_UINT64;
  Executable = FALSE;
  for (Index = 0; Index < Kernel->Count; Index++) {
    Segment = &Kernel->Segments[Index];
    Kernel->Base = MIN (Kernel->Base, Segment->Address);
    Kernel->End = MAX (Kernel->End, Segment->Address + Segment->Size);
    if ((Kernel->Entry >= Segment->Address) && (Kernel->Entry - Segment->Address < Segment->FileSize) &&
        ((Segment->Protection & 4) != 0)) { Executable = TRUE; }
    for (Other = 0; Other < Index; Other++) {
      if ((Segment->Address < Kernel->Segments[Other].Address + Kernel->Segments[Other].Size) &&
          (Kernel->Segments[Other].Address < Segment->Address + Segment->Size)) { return EFI_LOAD_ERROR; }
    }
  }
  if (!Executable || (Kernel->Entry & 3) || (Kernel->Base & EFI_PAGE_MASK) ||
      (Kernel->Base > MAX_UINT64 - WINDOW_SIZE) ||
      (Kernel->End - Kernel->Base > WINDOW_SIZE - SIZE_2MB)) { return EFI_LOAD_ERROR; }
  return EFI_SUCCESS;
}

// Fileset segment offsets are absolute in the collection. XNU rebases and
// signs its own fixup chains after entry; firmware only copies root mappings.
STATIC
EFI_STATUS
ParseKernel (CONST UINT8 *Data, UINTN Size, KERNEL *Kernel)
{
  EFI_STATUS Status;
  KERNEL     Member;
  UINTN      Offset;
  UINTN      End;
  UINTN      Header;
  UINTN      Name;
  UINTN      Index;
  UINTN      Other;
  UINT32     Length;
  BOOLEAN    Found;
  BOOLEAN    Covered;
  SEGMENT    *Child;
  SEGMENT    *Parent;

  Status = ParseKernelHeader (Data, Size, 0, Kernel);
  if (EFI_ERROR (Status) || (U32 (Data + 12) != 12)) { return Status; }
  Offset = 32;
  End = 32 + U32 (Data + 20);
  Found = FALSE;
  while (Offset < End) {
    Length = U32 (Data + Offset + 4);
    if (U32 (Data + Offset) == 0x80000035) {
      if (Length < 40) { return EFI_LOAD_ERROR; }
      Name = U32 (Data + Offset + 24);
      if ((Name < 32) || (Name >= Length)) { return EFI_LOAD_ERROR; }
      for (Index = Name; (Index < Length) && (Data[Offset + Index] != 0); Index++) {}
      if (Index == Length) { return EFI_LOAD_ERROR; }
      Header = U64 (Data + Offset + 16);
      if ((Header > Size) || (Size - Header < 32) || (Header & 7)) { return EFI_LOAD_ERROR; }
      // Every indexed header must actually be loaded at its advertised VA.
      Covered = FALSE;
      for (Other = 0; Other < Kernel->Count; Other++) {
        Parent = &Kernel->Segments[Other];
        if ((Header >= Parent->FileOffset) &&
            (Header - Parent->FileOffset <= Parent->FileSize) &&
            (32 <= Parent->FileSize - (Header - Parent->FileOffset)) &&
            (U64 (Data + Offset + 8) == Parent->Address + Header - Parent->FileOffset)) {
          Covered = TRUE;
        }
      }
      if (!Covered) { return EFI_LOAD_ERROR; }
      if ((Index - Name == sizeof ("com.apple.kernel") - 1) &&
          (CompareMem (Data + Offset + Name, "com.apple.kernel", sizeof ("com.apple.kernel")) == 0)) {
        if (Found || (U32 (Data + Header + 12) != 2) ||
            (U32 (Data + Header + 8) != U32 (Data + 8)) ||
            ((U32 (Data + Header + 24) & 0x80000000) == 0)) { return EFI_LOAD_ERROR; }
        Found = TRUE;
        Status = ParseKernelHeader (Data, Size, Header, &Member);
        if (EFI_ERROR (Status) || (Member.Entry != Kernel->Entry)) { return EFI_LOAD_ERROR; }
        for (Index = 0; Index < Member.Count; Index++) {
          Child = &Member.Segments[Index];
          Covered = FALSE;
          for (Other = 0; Other < Kernel->Count; Other++) {
            Parent = &Kernel->Segments[Other];
            if ((Child->Address >= Parent->Address) &&
                (Child->Address - Parent->Address <= Parent->Size) &&
                (Child->Size <= Parent->Size - (Child->Address - Parent->Address)) &&
                ((Child->Protection & ~Parent->Protection) == 0) &&
                ((Child->FileSize == 0) ||
                 ((Child->Address - Parent->Address <= Parent->FileSize) &&
                  (Child->FileSize <= Parent->FileSize - (Child->Address - Parent->Address)) &&
                  (Child->FileOffset == Parent->FileOffset + Child->Address - Parent->Address)))) {
              Covered = TRUE;
            }
          }
          if (!Covered) { return EFI_LOAD_ERROR; }
        }
      }
    }
    Offset += Length;
  }
  return Found ? EFI_SUCCESS : EFI_LOAD_ERROR;
}

STATIC
BOOLEAN
AdtNode (CONST UINT8 *Data, UINTN Size, UINTN *Offset, UINTN Depth, UINTN ParentPath, UINTN *RamdiskOffset, UINTN *TrustCacheOffset, UINTN *AddonOffset, UINTN *PolicyOffset, UINT64 *WindowSize, BOOLEAN *KeepPacked)
{
  UINT32 Properties;
  UINT32 Children;
  UINT32 Length;
  UINTN  Index;
  UINTN  Path;
  UINTN  Candidate;
  UINTN  TrustCandidate;
  UINTN  AddonCandidate;
  UINTN  PolicyCandidate;
  UINTN  MemoryCandidate;
  CONST UINT8 *Name;
  UINTN  NameLength;

  Name = NULL;
  NameLength = 0;
  Candidate = MAX_UINTN;
  TrustCandidate = MAX_UINTN;
  AddonCandidate = MAX_UINTN;
  PolicyCandidate = MAX_UINTN;
  MemoryCandidate = MAX_UINTN;
  if ((Depth > 64) || (Size - *Offset < 8)) { return AdtFail (__LINE__); }
  Properties = U32 (Data + *Offset);
  Children = U32 (Data + *Offset + 4);
  *Offset += 8;
  if (Properties > (Size - *Offset) / 36) { return AdtFail (__LINE__); }
  for (Index = 0; Index < Properties; Index++) {
    if (Size - *Offset < 36) { return AdtFail (__LINE__); }
    if (ScanMem8 (Data + *Offset, 32, 0) == NULL) { return AdtFail (__LINE__); }
    Length = U32 (Data + *Offset + 32);
    *Offset += 36;
    if (Length > Size - *Offset) { return AdtFail (__LINE__); }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "name") == 0) {
      if (Name != NULL) { return AdtFail (__LINE__); }
      Name = Data + *Offset;
      NameLength = Length;
    }
    if ((AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "RAMDisk") == 0) ||
        (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "PackedRAMDisk") == 0)) {
      if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "PackedRAMDisk") == 0) {
        if (*KeepPacked) { return AdtFail (__LINE__); }
        *KeepPacked = TRUE;
      }
      if ((Candidate != MAX_UINTN) || (Length != 16)) { return AdtFail (__LINE__); }
      Candidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "TrustCache") == 0) {
      if ((TrustCandidate != MAX_UINTN) || (Length != 16)) { return AdtFail (__LINE__); }
      TrustCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "GpuAddon") == 0) {
      if ((AddonCandidate != MAX_UINTN) || (Length != 16)) { return AdtFail (__LINE__); }
      AddonCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "RootPolicies") == 0) {
      if ((PolicyCandidate != MAX_UINTN) || (Length != 16)) { return AdtFail (__LINE__); }
      PolicyCandidate = *Offset;
    }
    if (AsciiStrCmp ((CONST CHAR8 *)(Data + *Offset - 36), "darwinboot-memory-size") == 0) {
      if ((MemoryCandidate != MAX_UINTN) || (Length != 8)) { return AdtFail (__LINE__); }
      MemoryCandidate = *Offset;
    }
    *Offset += Length;
    if (ALIGN_VALUE (*Offset, 4) > Size) { return AdtFail (__LINE__); }
    *Offset = ALIGN_VALUE (*Offset, 4);
  }
  Path = 3;
  if (Depth == 0) { Path = 0; }
  if ((Depth == 1) && (ParentPath == 0) && (NameLength == 7) && (CompareMem (Name, "chosen", 7) == 0)) { Path = 1; }
  if ((Depth == 2) && (ParentPath == 1) && (NameLength == 11) && (CompareMem (Name, "memory-map", 11) == 0)) { Path = 2; }
  if ((Path == 2) && (Candidate != MAX_UINTN)) {
    if (*RamdiskOffset != MAX_UINTN) { return AdtFail (__LINE__); }
    *RamdiskOffset = Candidate;
  }
  if ((Path == 2) && (TrustCandidate != MAX_UINTN)) {
    if (*TrustCacheOffset != MAX_UINTN) { return AdtFail (__LINE__); }
    *TrustCacheOffset = TrustCandidate;
  }
  if ((Path == 2) && (AddonCandidate != MAX_UINTN)) {
    if (*AddonOffset != MAX_UINTN) { return AdtFail (__LINE__); }
    *AddonOffset = AddonCandidate;
  }
  if (PolicyCandidate != MAX_UINTN) {
    if ((Path != 2) || (*PolicyOffset != MAX_UINTN)) { return AdtFail (__LINE__); }
    *PolicyOffset = PolicyCandidate;
  }
  if (MemoryCandidate != MAX_UINTN) {
    if ((Path != 1) || (*WindowSize != 0)) { return AdtFail (__LINE__); }
    *WindowSize = U64 (Data + MemoryCandidate);
    if (!DarwinWindowSizeValid (*WindowSize)) { return AdtFail (__LINE__); }
  }
  if (Children > (Size - *Offset) / 8) { return AdtFail (__LINE__); }
  for (Index = 0; Index < Children; Index++) {
    if (!AdtNode (Data, Size, Offset, Depth + 1, Path, RamdiskOffset, TrustCacheOffset, AddonOffset, PolicyOffset, WindowSize, KeepPacked)) { return AdtFail (__LINE__); }
  }
  return TRUE;
}

STATIC
BOOLEAN
ValidTrustCaches (CONST UINT8 *Data, UINTN Size)
{
  UINTN Count;
  UINTN Index;
  UINTN Start;
  UINTN End;
  UINTN Entries;
  UINTN Entry;

  if (Size < 8) { return AdtFail (__LINE__); }
  Count = U32 (Data);
  if ((Count == 0) || (Count > 128) || (Count > (Size - 4) / 4)) { return AdtFail (__LINE__); }
  for (Index = 0; Index < Count; Index++) {
    Start = U32 (Data + 4 + Index * 4);
    End = (Index + 1 < Count) ? U32 (Data + 8 + Index * 4) : Size;
    if ((Start < 4 + Count * 4) || (Start & 3) || (End > Size) ||
        (End < Start) || (End - Start < 24) || (U32 (Data + Start) != 2)) { return AdtFail (__LINE__); }
    Entries = U32 (Data + Start + 20);
    if ((Entries > (End - Start - 24) / 24) || (End - Start != 24 + Entries * 24)) { return AdtFail (__LINE__); }
    for (Entry = 0; Entry < Entries; Entry++) {
      CONST UINT8 *Hash = Data + Start + 24 + Entry * 24;
      if ((Hash[20] < 1) || (Hash[20] > 4) ||
          ((Entry != 0) && (CompareMem (Hash - 24, Hash, 20) >= 0))) { return AdtFail (__LINE__); }
    }
  }
  return TRUE;
}

STATIC
EFI_STATUS
GetMap (EFI_MEMORY_DESCRIPTOR **Map, UINTN *Capacity, UINTN *Size, UINTN *Key, UINTN *Stride)
{
  EFI_STATUS Status;
  UINT32     Version;
  UINTN      Attempt;

  for (Attempt = 0; Attempt < 3; Attempt++) {
    *Size = *Capacity;
    Status = gBS->GetMemoryMap (Size, *Map, Key, Stride, &Version);
    if (Status != EFI_BUFFER_TOO_SMALL) { return Status; }
    if (*Map != NULL) { FreePool (*Map); }
    *Capacity = *Size + 32 * sizeof (EFI_MEMORY_DESCRIPTOR);
    *Map = AllocatePool (*Capacity);
    if (*Map == NULL) { return EFI_OUT_OF_RESOURCES; }
  }
  return EFI_OUT_OF_RESOURCES;
}

// End of the run of EfiConventionalMemory that begins at Start: the UEFI map often lists physically
// adjacent free ranges as separate descriptors, so extend over every descriptor that continues the run.
STATIC
UINT64
RunEnd (EFI_MEMORY_DESCRIPTOR *Map, UINTN Size, UINTN Stride, UINT64 Start, UINT64 End)
{
  EFI_MEMORY_DESCRIPTOR *Descriptor;
  UINTN                 Offset;
  BOOLEAN               Extended;

  do {
    Extended = FALSE;
    for (Offset = 0; Offset + Stride <= Size; Offset += Stride) {
      Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
      if ((Descriptor->Type == EfiConventionalMemory) && (Descriptor->PhysicalStart == End) &&
          (Descriptor->NumberOfPages != 0) && (Descriptor->NumberOfPages < (MAX_UINT64 - End) / EFI_PAGE_SIZE)) {
        End += EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages);
        Extended = TRUE;
      }
    }
  } while (Extended);
  (VOID)Start;
  return End;
}

// Large diagnostic text straight into the GOP framebuffer: the UEFI text console font is too small to
// photograph. 5x12 glyphs from DiagFont.h scaled 4x, white on a black box; wraps at the right edge.
#include "DiagFont.h"
STATIC CONST UINT64 mDiagFont[] = GLYPH_FONT;

STATIC
VOID
DiagDraw (CONST CHAR16 *Text, UINTN Row)
{
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;
  UINT64                       Video[6];
  UINTN                        Scale = 4, X = 0, Y, Index, Gx, Gy, Dx, Dy, Cell, Line;
  UINT32                       *Fb;
  UINT64                       Glyph, Data;
  CHAR16                       Ch;

  if (EFI_ERROR (gBS->LocateProtocol (&gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop)) ||
      EFI_ERROR (DarwinBootVideoFromGop (Gop, Video))) { return; }
  Cell = 6 * Scale;
  Line = 14 * Scale;
  Y = Video[4] / 4 + Row * Line;
  Fb = (UINT32 *)(UINTN)Video[0];
  for (Index = 0; Text[Index] != 0; Index++) {
    Ch = Text[Index];
    if ((Ch < 32) || (Ch > 126)) { continue; }
    if (X + Cell > Video[3]) { X = 0; Y += Line; }
    if (Y + Line > Video[4]) { return; }
    Glyph = mDiagFont[Ch - 32];
    for (Gy = 0; Gy < 14 * Scale; Gy++) {
      for (Gx = 0; Gx < Cell; Gx++) {
        Fb[(Y + Gy) * (Video[2] / 4) + X + Gx] = 0xFF000000;
      }
    }
    for (Gy = 0; Gy < 12; Gy++) {
      Data = (Gy < 6) ? ((Glyph >> 32) >> (Gy * 5)) : ((Glyph & 0xFFFFFFFFULL) >> ((Gy - 6) * 5));
      for (Gx = 0; Gx < 5; Gx++) {
        if ((Data >> Gx) & 1) {
          for (Dy = 0; Dy < Scale; Dy++) {
            for (Dx = 0; Dx < Scale; Dx++) {
              Fb[(Y + Gy * Scale + Dy) * (Video[2] / 4) + X + Gx * Scale + Dx] = 0xFFFFFFFF;
            }
          }
        }
      }
    }
    X += Cell;
  }
}

STATIC
EFI_STATUS
AllocateWindow (KERNEL *Kernel, UINT64 WindowSize, EFI_PHYSICAL_ADDRESS *Address)
{
  EFI_MEMORY_DESCRIPTOR *Map;
  EFI_MEMORY_DESCRIPTOR *Descriptor;
  EFI_STATUS            Status;
  UINTN                 Capacity;
  UINTN                 Size;
  UINTN                 Key;
  UINTN                 Stride;
  UINTN                 Offset;
  UINT64                End;
  UINT64                Candidate;
  UINT64                BestStart;
  UINT64                BestBytes;
  UINT64                RunBytes;

  *Address = 0;
  Map = NULL;
  Capacity = 0;
  BestStart = 0;
  BestBytes = 0;
  Status = GetMap (&Map, &Capacity, &Size, &Key, &Stride);
  if (EFI_ERROR (Status)) { if (Map != NULL) { FreePool (Map); } return Status; }
  Status = EFI_OUT_OF_RESOURCES;
  for (Offset = 0; Offset + Stride <= Size; Offset += Stride) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
    if ((Descriptor->Type != EfiConventionalMemory) || (Descriptor->NumberOfPages == 0)) { continue; }
    End = RunEnd (Map, Size, Stride, Descriptor->PhysicalStart,
                  Descriptor->PhysicalStart + EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages));
    RunBytes = End - Descriptor->PhysicalStart;
    if (RunBytes > BestBytes) { BestBytes = RunBytes; BestStart = Descriptor->PhysicalStart; }
    Candidate = ALIGN_VALUE (Descriptor->PhysicalStart, BLOCK_SIZE) + (Kernel->Base & (BLOCK_SIZE - 1));
    if ((Candidate < Descriptor->PhysicalStart) || (End < Candidate) || (End - Candidate < WindowSize)) { continue; }
    Status = gBS->AllocatePages (AllocateAddress, EfiLoaderCode, EFI_SIZE_TO_PAGES (WindowSize), &Candidate);
    if (!EFI_ERROR (Status)) { *Address = Candidate; break; }
  }
  if (EFI_ERROR (Status)) {
    CHAR16 Line[96];
    UINTN  Row = 1;
    UnicodeSPrint (Line, sizeof (Line), L"NO WINDOW %lx BIG RUN %lx @ %lx", WindowSize, BestBytes, BestStart);
    DiagDraw (Line, 0);
    for (Offset = 0; Offset + Stride <= Size; Offset += Stride) {
      Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
      if ((Descriptor->Type == EfiConventionalMemory) && (Descriptor->NumberOfPages >= 0x400) && (Row < 8)) {
        UnicodeSPrint (Line, sizeof (Line), L"FREE %lx + %lx", Descriptor->PhysicalStart, EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages));
        DiagDraw (Line, Row++);
      }
    }

  }
  FreePool (Map);
  return Status;
}

STATIC
VOID
DiagHang (
  IN CONST CHAR16 *Text
  )
{
  DiagDraw (Text, 0);
  for (;;) {
    __asm__ __volatile__ ("yield");
  }
}

STATIC
EFI_STATUS
EFIAPI
Boot (
  IN UNIXNU_LOADER_PROTOCOL    *This,
  IN CONST UNIXNU_LOADER_BOOT_REQUEST *Request
  )
{
  EFI_STATUS                      Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *Fs;
  EFI_FILE_PROTOCOL               *Root;
  VOID                            *Image;
  VOID                            *Tree;
  VOID                            *TrustCaches;
  VOID                            *Addon;
  UINTN                           ImageSize;
  UINTN                           TreeSize;
  UINTN                           TrustCacheSize;
  UINTN                           AddonSize;
  CHAR16                          *TreePath;
  UINTN                           Length;
  UINTN                           Index;
  UINTN                           Offset;
  KERNEL                          Kernel;
  EFI_PHYSICAL_ADDRESS            Address;
  UINT64                          ArgsAddress;
  UINT64                          TreeAddress;
  UINT64                          Used;
  UINT64                          WindowSize;
  UINT64                          RamdiskAddress;
  UINTN                           RamdiskOffset;
  UINTN                           RamdiskBytes;
  UINTN                           RamdiskExpandedSize;
  BOOLEAN                         RamdiskPacked;
  BOOLEAN                         KeepPacked;
  UINTN                           TrustCacheOffset;
  UINT64                          TrustCacheAddress;
  UINTN                           AddonOffset;
  UINT64                          AddonAddress;
  VOID                            *Policies;
  UINTN                           PolicySize;
  UINTN                           PolicyOffset;
  UINT64                          PolicyAddress;
  DARWIN_BOOT_ARGS                *Args;
  EFI_MEMORY_DESCRIPTOR           *Map;
  UINTN                           Capacity;
  UINTN                           MapSize;
  UINTN                           Key;
  UINTN                           Stride;
  UINT32                          Version;
  UINTN                           Attempt;
  CHAR8                           CommandLine[1024];
  CHAR16                          Line[160];
  UINT64                          Video[6];

  (VOID)This;
  if ((Request == NULL) || (Request->Volume == NULL) || (Request->KernelPath == NULL)) { return EFI_INVALID_PARAMETER; }
  if ((Request->KextCount != 0) || (Request->DeviceTree != NULL) || (Request->DeviceTreeSize != 0) ||
      (DarwinCurrentEl () != 4)) {
    Print (L"DARWINBOOT: unsupported inputs or exception level; firmware retained\n");
    return EFI_UNSUPPORTED;
  }
  if (!RamdiskLayout (Request->Ramdisk, Request->RamdiskSize, &RamdiskExpandedSize, &RamdiskPacked)) {
    Print (L"DARWINBOOT: ramdisk layout rejected, %lu bytes\n", (UINT64)Request->RamdiskSize);
    return EFI_BAD_BUFFER_SIZE;
  }
  ZeroMem (CommandLine, sizeof (CommandLine));
  if (Request->BootArgs != NULL) {
    for (Index = 0; Request->BootArgs[Index] != 0; Index++) {
      if ((Index >= sizeof (CommandLine) - 1) || (Request->BootArgs[Index] > 0x7f)) {
        Print (L"DARWINBOOT: boot args rejected at %lu\n", (UINT64)Index);
        return EFI_BAD_BUFFER_SIZE;
      }
      CommandLine[Index] = (CHAR8)Request->BootArgs[Index];
    }
  }
  Root = NULL;
  Image = NULL;
  Tree = NULL;
  TrustCaches = NULL;
  Addon = NULL;
  AddonSize = 0;
  Policies = NULL;
  PolicySize = 0;
  TreePath = NULL;
  Map = NULL;
  Address = 0;
  Capacity = 0;
  Status = gBS->HandleProtocol (Request->Volume, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR (Status)) { return Status; }
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) { return Status; }
  Length = StrSize (Request->KernelPath);
  TreePath = AllocatePool (Length + 11 * sizeof (CHAR16));
  if (TreePath == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Fail; }
  CopyMem (TreePath, Request->KernelPath, Length);
  StrCatS (TreePath, Length / sizeof (CHAR16) + 11, L".adt");
  Status = ReadFile (Root, TreePath, SIZE_16MB, &Tree, &TreeSize);
  if (EFI_ERROR (Status)) { goto Fail; }
  CopyMem (TreePath, Request->KernelPath, Length);
  StrCatS (TreePath, Length / sizeof (CHAR16) + 11, L".trustcache");
  Status = ReadFile (Root, TreePath, SIZE_16MB, &TrustCaches, &TrustCacheSize);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) { goto Fail; }
  CopyMem (TreePath, Request->KernelPath, Length);
  StrCatS (TreePath, Length / sizeof (CHAR16) + 11, L".vroot");
  Status = ReadFile (Root, TreePath, SIZE_128MB, &Policies, &PolicySize);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) { goto Fail; }
  /*
   * The kernel may be split into .0/.1 parts: this board's loader reads back stale bytes past ~90 MiB
   * of the FAT volume, so each part stays under that. Read the parts and join them.
   */
  {
    CHAR16 PartPath[256];
    UINTN  Part;
    VOID   *PartData;
    UINTN  PartSize;
    Image = NULL;
    ImageSize = 0;
    for (Part = 0; Part < 2; Part++) {
      CopyMem (PartPath, Request->KernelPath, Length);
      /* Length is StrSize: it includes the terminator, so the '.' takes the terminator's slot. */
      PartPath[Length / sizeof (CHAR16) - 1] = L'.';
      PartPath[Length / sizeof (CHAR16)] = (CHAR16)(L'0' + Part);
      PartPath[Length / sizeof (CHAR16) + 1] = 0;
      Status = ReadFile (Root, PartPath, SIZE_128MB, &PartData, &PartSize);
      if (EFI_ERROR (Status)) {
        if (Part == 1 && Status == EFI_NOT_FOUND) {
          break;                       /* an unsplit kernel, already read as part 0 */
        }
        if (Part == 0) { goto Fail; }
        break;
      }
      if (Image == NULL) {
        Image = PartData;
        ImageSize = PartSize;
      } else {
        UINT8 *Joined = AllocateZeroPool (ImageSize + PartSize);
        if (Joined == NULL) { FreePool (PartData); Status = EFI_OUT_OF_RESOURCES; goto Fail; }
        CopyMem (Joined, Image, ImageSize);
        CopyMem (Joined + ImageSize, PartData, PartSize);
        FreePool (Image);
        FreePool (PartData);
        Image = Joined;
        ImageSize += PartSize;
      }
    }
    if (Image == NULL) { goto Fail; }
  }
  Status = ParseKernel (Image, ImageSize, &Kernel);
  if (EFI_ERROR (Status)) { goto Fail; }
  Offset = 0;
  RamdiskOffset = MAX_UINTN;
  TrustCacheOffset = MAX_UINTN;
  AddonOffset = MAX_UINTN;
  PolicyOffset = MAX_UINTN;
  WindowSize = 0;
  KeepPacked = FALSE;
  if (!AdtNode (Tree, TreeSize, &Offset, 0, 3, &RamdiskOffset, &TrustCacheOffset, &AddonOffset, &PolicyOffset, &WindowSize, &KeepPacked) || (Offset != TreeSize)) {
    UnicodeSPrint (Line, sizeof (Line), L"ADT l=%u off=%lx sz=%lx w=%x,%x,%x,%x",
                   (UINT32)mAdtFailLine, (UINT64)Offset, (UINT64)TreeSize,
                   U32 (Tree), U32 ((UINT8 *)Tree + 4), U32 ((UINT8 *)Tree + 8), U32 ((UINT8 *)Tree + 12));
    DiagHang (Line);
  }
  if (KeepPacked && (!RamdiskPacked || (RamdiskOffset == MAX_UINTN))) {
    UnicodeSPrint (Line, sizeof (Line), L"KEEP rp=%u rd=%lx rs=%lx",
                   (UINT32)RamdiskPacked, (UINT64)RamdiskOffset, (UINT64)Request->RamdiskSize);
    DiagHang (Line);
  }
  if (WindowSize == 0) { WindowSize = WINDOW_SIZE; }
  if (Kernel.Base > MAX_UINT64 - WindowSize) { Status = EFI_LOAD_ERROR; goto Fail; }
  if (Request->Ramdisk != NULL) {
    if ((RamdiskOffset == MAX_UINTN) || (U64 ((UINT8 *)Tree + RamdiskOffset) != 0) ||
        (U64 ((UINT8 *)Tree + RamdiskOffset + 8) != 0)) {
      UnicodeSPrint (Line, sizeof (Line), L"RD off=%lx v0=%lx v8=%lx", (UINT64)RamdiskOffset,
                     (RamdiskOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + RamdiskOffset),
                     (RamdiskOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + RamdiskOffset + 8));
      DiagHang (Line);
    }
  } else if (RamdiskOffset != MAX_UINTN) {
    Status = EFI_UNSUPPORTED;
    goto Fail;
  }
  if (TrustCaches != NULL) {
    if ((TrustCacheOffset == MAX_UINTN) || (U64 ((UINT8 *)Tree + TrustCacheOffset) != 0) ||
        (U64 ((UINT8 *)Tree + TrustCacheOffset + 8) != 0) || !ValidTrustCaches (TrustCaches, TrustCacheSize)) {
      UnicodeSPrint (Line, sizeof (Line), L"TC off=%lx sz=%lx m0=%lx m8=%lx ok=%u", (UINT64)TrustCacheOffset,
                     (UINT64)TrustCacheSize,
                     (TrustCacheOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + TrustCacheOffset),
                     (TrustCacheOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + TrustCacheOffset + 8),
                     ValidTrustCaches (TrustCaches, TrustCacheSize) ? 1 : 0);
      DiagHang (Line);
    }
  } else if (TrustCacheOffset != MAX_UINTN) {
    UnicodeSPrint (Line, sizeof (Line), L"TC MISS off=%lx", (UINT64)TrustCacheOffset);
    DiagHang (Line);
  }
  //
  // The GPU addon (kernel.macho.gpuaddon, scripts/make-gpu-addon.py): files the kernel writes into the Data volume before its addon
  // mounts. Only its header is checked here; the kernel validates every entry.
  //
  CopyMem (TreePath, Request->KernelPath, Length);
  StrCatS (TreePath, Length / sizeof (CHAR16) + 11, L".gpuaddon");
  Status = ReadFile (Root, TreePath, SIZE_64MB, &Addon, &AddonSize);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) { goto Fail; }
  if (Addon != NULL) {
    if ((AddonOffset == MAX_UINTN) || (U64 ((UINT8 *)Tree + AddonOffset) != 0) || (U64 ((UINT8 *)Tree + AddonOffset + 8) != 0) ||
        (AddonSize < 24) || (CompareMem (Addon, "NGPUADD2", 8) != 0) || (U64 ((UINT8 *)Addon + 16) != AddonSize)) {
      UnicodeSPrint (Line, sizeof (Line), L"AD off=%lx sz=%lx m0=%lx m8=%lx",
                     (UINT64)AddonOffset, (UINT64)AddonSize,
                     (AddonOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + AddonOffset),
                     (AddonOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + AddonOffset + 8));
      DiagHang (Line);
    }
  } else if (AddonOffset != MAX_UINTN) {
    UnicodeSPrint (Line, sizeof (Line), L"AD MISS off=%lx", (UINT64)AddonOffset);
    DiagHang (Line);
  }
  // Root hash tables live outside the kernel's coalesced constant segments.
  // The kernel authenticates each envelope against its compiled owner anchor.
  if (Policies != NULL) {
    if ((PolicyOffset == MAX_UINTN) || (U64 ((UINT8 *)Tree + PolicyOffset) != 0) ||
        (U64 ((UINT8 *)Tree + PolicyOffset + 8) != 0) || (PolicySize < 32) ||
        (CompareMem (Policies, "VROOTB01", 8) != 0) || (U64 ((UINT8 *)Policies + 8) != 1) ||
        (U64 ((UINT8 *)Policies + 16) == 0) || (U64 ((UINT8 *)Policies + 16) > 16) ||
        (U64 ((UINT8 *)Policies + 24) != PolicySize)) {
      UnicodeSPrint (Line, sizeof (Line), L"POL off=%lx sz=%lx m0=%lx m8=%lx mgk=%x",
                     (UINT64)PolicyOffset, (UINT64)PolicySize,
                     (PolicyOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + PolicyOffset),
                     (PolicyOffset == MAX_UINTN) ? 0 : U64 ((UINT8 *)Tree + PolicyOffset + 8),
                     (UINT32)U64 (Policies));
      DiagHang (Line);
    }
  } else if (PolicyOffset != MAX_UINTN) {
    UnicodeSPrint (Line, sizeof (Line), L"POL MISS off=%lx", (UINT64)PolicyOffset);
    DiagHang (Line);
  }
  Status = ReadBootVideo (Video);
  if (EFI_ERROR (Status)) { goto Fail; }
  Status = AllocateWindow (&Kernel, WindowSize, &Address);
  if (EFI_ERROR (Status)) { goto Fail; }
  ArgsAddress = ALIGN_VALUE (Address + Kernel.End - Kernel.Base, SIZE_16KB);
  TreeAddress = ArgsAddress + EFI_PAGE_SIZE;
  RamdiskAddress = ALIGN_VALUE (TreeAddress + TreeSize, EFI_PAGE_SIZE);
  RamdiskBytes = ALIGN_VALUE (KeepPacked ? Request->RamdiskSize : RamdiskExpandedSize, EFI_PAGE_SIZE);
  TrustCacheAddress = RamdiskAddress + RamdiskBytes;
  AddonAddress = ALIGN_VALUE (TrustCacheAddress + TrustCacheSize, SIZE_16KB);
  PolicyAddress = ALIGN_VALUE (AddonAddress + AddonSize, SIZE_16KB);
  Used = ALIGN_VALUE (PolicyAddress + PolicySize, SIZE_16KB) - Address;
  if (Used > WindowSize - BLOCK_SIZE) {
    Print (L"DARWINBOOT: used %lu window %lu kernel %lu ramdisk %lu\n", (UINT64)Used, (UINT64)WindowSize, (UINT64)(Kernel.End - Kernel.Base), (UINT64)RamdiskBytes);
    Status = EFI_BAD_BUFFER_SIZE;
    goto Fail;
  }
  ZeroMem ((VOID *)(UINTN)Address, (UINTN)Used);
  for (Index = 0; Index < Kernel.Count; Index++) {
    CopyMem ((VOID *)(UINTN)(Address + Kernel.Segments[Index].Address - Kernel.Base),
             (UINT8 *)Image + Kernel.Segments[Index].FileOffset, (UINTN)Kernel.Segments[Index].FileSize);
  }
  Args = (DARWIN_BOOT_ARGS *)(UINTN)ArgsAddress;
  Args->Revision = 2;
  Args->Version = 2;
  Args->VirtualBase = Kernel.Base;
  Args->PhysicalBase = Address;
  Args->MemorySize = WindowSize;
  Args->MemorySizeActual = WindowSize;
  Args->TopOfKernelData = Address + Used;
  CopyMem (Args->Video, Video, sizeof (Video));
  Args->DeviceTree = Kernel.Base + TreeAddress - Address;
  Args->DeviceTreeLength = (UINT32)TreeSize;
  CopyMem (Args->CommandLine, CommandLine, sizeof (CommandLine));
  CopyMem ((VOID *)(UINTN)TreeAddress, Tree, TreeSize);
  if (Request->Ramdisk != NULL) {
    if (KeepPacked) { CopyMem ((VOID *)(UINTN)RamdiskAddress, Request->Ramdisk, Request->RamdiskSize); }
    else { CopyRamdisk ((VOID *)(UINTN)RamdiskAddress, Request->Ramdisk, Request->RamdiskSize, RamdiskPacked); }
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + RamdiskOffset), RamdiskAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + RamdiskOffset + 8), KeepPacked ? Request->RamdiskSize : RamdiskBytes);
  }
  if (TrustCaches != NULL) {
    CopyMem ((VOID *)(UINTN)TrustCacheAddress, TrustCaches, TrustCacheSize);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + TrustCacheOffset), TrustCacheAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + TrustCacheOffset + 8), TrustCacheSize);
    FreePool (TrustCaches); TrustCaches = NULL;
  }
  if (Addon != NULL) {
    CopyMem ((VOID *)(UINTN)AddonAddress, Addon, AddonSize);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + AddonOffset), AddonAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + AddonOffset + 8), AddonSize);
    FreePool (Addon); Addon = NULL;
  }
  if (Policies != NULL) {
    CopyMem ((VOID *)(UINTN)PolicyAddress, Policies, PolicySize);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + PolicyOffset), PolicyAddress);
    WriteUnaligned64 ((UINT64 *)(UINTN)(TreeAddress + PolicyOffset + 8), PolicySize);
    FreePool (Policies); Policies = NULL;
  }
  /*
   * Bring-up sampler: does the kernel read buffer and the copied window hold the collection's bytes at known
   * file offsets? 0x5f67c rodata text, 0x5a14008 a chain word in __static_if, 0x5acfa90 the __static_ifinit
   * pointers. The expected values are read from the same kernel.macho on the host.
   */
  {
    CHAR16 Probe[160];
    UINT64 Crc = 0;
    UINT64 CrcA = 0;
    UINT64 CrcB = 0;
    UINT64 CrcC = 0;
    UINTN  At;
    UINT64 Sum = 0;
    /*
     * Layout-independent check: a chunked sum over the whole read buffer and over every byte the
     * window received. Equal sums mean the image reached memory complete; a difference means the
     * FAT read lost or mangled bytes long before the kernel runs. (The fixed-offset samples below
     * only make sense for one segment layout; these two numbers do not depend on it.)
     */
    for (At = 0; At + 8 <= ImageSize; At += 8) {
      UINT64 Word = ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + At));
      Crc = (Crc * 0x100000001b3ULL) ^ Word;
      /* Quarter sums name the damaged region without another round trip. */
      if (At < ImageSize / 4) {
        CrcA = (CrcA * 0x100000001b3ULL) ^ Word;
      } else if (At < ImageSize / 2) {
        CrcB = (CrcB * 0x100000001b3ULL) ^ Word;
      } else if (At < (ImageSize / 4) * 3) {
        CrcC = (CrcC * 0x100000001b3ULL) ^ Word;
      }
    }
    for (At = 0; At < Kernel.Count; At++) {
      UINT64 Left = Kernel.Segments[At].FileSize;
      UINT8 *From = (UINT8 *)Image + Kernel.Segments[At].FileOffset;
      UINT8 *To = (UINT8 *)(UINTN)(Address + Kernel.Segments[At].Address - Kernel.Base);
      while (Left >= 8) {
        Sum += ReadUnaligned64 ((CONST UINT64 *)From) ^ ReadUnaligned64 ((CONST UINT64 *)To);
        From += 8; To += 8; Left -= 8;
      }
    }
    /* The tail samples come first: the row 1/2 area stays clear of later firmware output. */
    UnicodeSPrint (Probe, sizeof (Probe), L"E1 %lx %lx %lx",
                   ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + ImageSize - 901120)),
                   ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + ImageSize - 815432)),
                   ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + ImageSize - 744680)));
    DiagDraw (Probe, 1);
    UnicodeSPrint (Probe, sizeof (Probe), L"E2 %lx %lx %lx",
                   ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + ImageSize - 673928)),
                   ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + ImageSize - 603176)),
                   ReadUnaligned64 ((CONST UINT64 *)((UINT8 *)Image + ImageSize - 531888)));
    DiagDraw (Probe, 2);
    UnicodeSPrint (Probe, sizeof (Probe), L"CRC %lx bytes %lx segs %lx",
                   Crc, (UINT64)ImageSize, (UINT64)Kernel.Count);
    DiagDraw (Probe, 5);
    UnicodeSPrint (Probe, sizeof (Probe), L"WINDOW delta %lx (0 = identical)",
                   Sum);
    DiagDraw (Probe, 6);
    /*
     * Find the first 64 KiB window where the read buffer disagrees with the copy that went into the
     * kernel window. KernelSegments maps a file offset to both sides, so this needs no host
     * reference: it names the offset where the FAT read stopped matching what it copied.
     */
    {
      UINTN FirstBad = 0xFFFFFFFF;
      UINTN BadCount = 0;
      UINTN Seg;
      for (Seg = 0; Seg < Kernel.Count; Seg++) {
        UINT64 Left = Kernel.Segments[Seg].FileSize;
        UINT8 *From = (UINT8 *)Image + Kernel.Segments[Seg].FileOffset;
        UINT8 *To = (UINT8 *)(UINTN)(Address + Kernel.Segments[Seg].Address - Kernel.Base);
        UINT64 FileOff = Kernel.Segments[Seg].FileOffset;
        while (Left >= 0x10000) {
          UINTN At2;
          UINTN Same = 1;
          for (At2 = 0; At2 < 0x10000; At2 += 8) {
            if (ReadUnaligned64 ((CONST UINT64 *)(From + At2)) !=
                ReadUnaligned64 ((CONST UINT64 *)(To + At2))) {
              Same = 0;
              break;
            }
          }
          if (!Same) {
            if (BadCount == 0) {
              FirstBad = (UINTN)FileOff;
            }
            BadCount++;
          }
          From += 0x10000; To += 0x10000; Left -= 0x10000; FileOff += 0x10000;
        }
      }
      UnicodeSPrint (Probe, sizeof (Probe), L"BAD off %lx n %lx", (UINT64)FirstBad, (UINT64)BadCount);
      DiagDraw (Probe, 7);
    }
    /*
     * Report physical ranges, rather than guessing file LBAs from an older
     * FAT layout. ABL rewrites the initrd address in the live FDT.
     */
    {
      UKE_MEM_STATUS *Mem = NULL;
      EFI_STATUS MemStatus = EfiGetSystemConfigurationTable (&gUkeMemStatusGuid, (VOID **)&Mem);
      if (!EFI_ERROR (MemStatus) && (Mem != NULL) && (Mem->Magic == UKE_MEM_STATUS_MAGIC)) {
        UINT64 ImageBase = (UINT64)(UINTN)Image;
        UINT64 Overlap = (ImageBase < Mem->InitrdEnd) && (Mem->InitrdStart < ImageBase + ImageSize);
        UnicodeSPrint (Probe, sizeof (Probe), L"INITRD %lx-%lx", Mem->InitrdStart, Mem->InitrdEnd);
        DiagDraw (Probe, 8);
        UnicodeSPrint (Probe, sizeof (Probe), L"IMAGE %lx +%lx overlap %lx", ImageBase, (UINT64)ImageSize, Overlap);
        DiagDraw (Probe, 9);
        UnicodeSPrint (Probe, sizeof (Probe), L"FDT %lx +%lx WINDOW %lx", Mem->Dtb, Mem->DtbSize, Address);
        DiagDraw (Probe, 10);
      }
    }
    /* Continue immediately after diagnostics; the validated loader no longer needs a photo hold. */
  }
  FreePool (Image); Image = NULL;
  FreePool (Tree); Tree = NULL;
  FreePool (TreePath); TreePath = NULL;
  Root->Close (Root); Root = NULL;
  Status = GetMap (&Map, &Capacity, &MapSize, &Key, &Stride);
  if (EFI_ERROR (Status)) { goto Fail; }
  Print (L"DARWINBOOT: ARM64 va=0x%lx pa=0x%lx args=0x%lx entry=0x%lx owned=0x%lx\n",
         Kernel.Base, Address, ArgsAddress, Address + Kernel.Entry - Kernel.Base, (UINT64)WindowSize);
  Print (L"DARWINBOOT: video base=0x%lx display=%lu row=%lu width=%lu height=%lu depth=%lu\n",
         Video[0], Video[1], Video[2], Video[3], Video[4], Video[5]);
  Print (L"DARWINBOOT: command line: %a\n", CommandLine);
  Print (L"DARWINBOOT: inputs validated; exiting boot services\n");

  //
  // The same facts in large type over the whole screen. The firmware's log
  // draws far larger than the text console, and the form feed clears the
  // screen first. This is what stays visible if the kernel never draws.
  //
  DEBUG ((DEBUG_ERROR, "\fDARWINBOOT: hand-off to the kernel\n\n"));
  DEBUG ((DEBUG_ERROR, "kernel   va 0x%lx  pa 0x%lx\n", Kernel.Base, Address));
  DEBUG ((DEBUG_ERROR, "entry    pa 0x%lx\n", Address + Kernel.Entry - Kernel.Base));
  DEBUG ((DEBUG_ERROR, "args     pa 0x%lx  window 0x%lx bytes\n", ArgsAddress, (UINT64)WindowSize));
  DEBUG ((DEBUG_ERROR, "video    base 0x%lx  %lux%lu  row %lu bytes  %lu bpp\n", Video[0], Video[3], Video[4], Video[2], Video[5]));
  DEBUG ((DEBUG_ERROR, "entry words %08x %08x %08x %08x\n",
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base)),
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base + 4)),
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base + 8)),
          ReadUnaligned32 ((CONST UINT32 *)(UINTN)(Address + Kernel.Entry - Kernel.Base + 12))));
  DEBUG ((DEBUG_ERROR, "CurrentEL %lu  SCTLR_EL1 0x%lx  TCR_EL1 0x%lx\n", DarwinCurrentEl () >> 2, READ_SYSREG (sctlr_el1), READ_SYSREG (tcr_el1)));
  DEBUG ((DEBUG_ERROR, "ID_AA64MMFR0_EL1 0x%lx  (PARange %lu, 4 KiB granule %a)\n", READ_SYSREG (id_aa64mmfr0_el1),
          READ_SYSREG (id_aa64mmfr0_el1) & 0xF, (((READ_SYSREG (id_aa64mmfr0_el1) >> 28) & 0xF) == 0xF) ? "NOT supported" : "supported"));
  DEBUG ((DEBUG_ERROR, "ID_AA64PFR0_EL1  0x%lx\n", READ_SYSREG (id_aa64pfr0_el1)));
  DEBUG ((DEBUG_ERROR, "\nExiting boot services. A green bar across the top\nmarks the loader handoff before the kernel branch.\n"));
  for (Attempt = 0; Attempt < 3; Attempt++) {
    MapSize = Capacity;
    Status = gBS->GetMemoryMap (&MapSize, Map, &Key, &Stride, &Version);
    if (EFI_ERROR (Status)) {
      if (Attempt == 0) { goto Fail; }
      CpuDeadLoop ();
    }
    Status = gBS->ExitBootServices (mImage, Key);
    if (!EFI_ERROR (Status)) {
      DarwinEnter (ArgsAddress, Address + Kernel.Entry - Kernel.Base, Address, WindowSize, Video[0], Video[2] * Video[4]);
      CpuDeadLoop ();
    }
    if (Status != EFI_INVALID_PARAMETER) { CpuDeadLoop (); }
  }
  CpuDeadLoop ();
  return EFI_ABORTED;
Fail:
  if (Root != NULL) { Root->Close (Root); }
  if (Image != NULL) { FreePool (Image); }
  if (Tree != NULL) { FreePool (Tree); }
  if (TrustCaches != NULL) { FreePool (TrustCaches); }
  if (Addon != NULL) { FreePool (Addon); }
  if (Policies != NULL) { FreePool (Policies); }
  if (TreePath != NULL) { FreePool (TreePath); }
  if (Map != NULL) { FreePool (Map); }
  if (Address != 0) { gBS->FreePages (Address, EFI_SIZE_TO_PAGES (WindowSize)); }
  Print (L"DARWINBOOT: boot refused: %r; firmware retained\n", Status);
  return Status;
}

STATIC UNIXNU_LOADER_PROTOCOL mLoader = { UNIXNU_LOADER_REVISION, Boot };

STATIC
EFI_STATUS
EFIAPI
Unload (EFI_HANDLE ImageHandle)
{
  return gBS->UninstallMultipleProtocolInterfaces (ImageHandle, &gUniXNULoaderProtocolGuid, &mLoader, NULL);
}

EFI_STATUS
EFIAPI
DarwinBootEntry (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_LOADED_IMAGE_PROTOCOL *Loaded;
  EFI_STATUS               Status;
  VOID                     *Existing;

  (VOID)SystemTable;
  Status = gBS->LocateProtocol (&gUniXNULoaderProtocolGuid, NULL, &Existing);
  if (!EFI_ERROR (Status)) { return EFI_ALREADY_STARTED; }
  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Loaded);
  if (EFI_ERROR (Status)) { return Status; }
  mImage = ImageHandle;
  Status = gBS->InstallMultipleProtocolInterfaces (&ImageHandle, &gUniXNULoaderProtocolGuid, &mLoader, NULL);
  if (!EFI_ERROR (Status)) {
    Loaded->Unload = Unload;
    Print (L"DARWINBOOT: loader v2 installed EL%u\n", (UINT32)(DarwinCurrentEl () >> 2));
  }
  return Status;
}
