# Patch Description

本文档用于介绍本人实现的 ILP32 相关的 GNU 工具链 Patch，RV64 ILP32在本文档中简称为新32位

## GCC Patch Description

本部分 Patch 参考了 AArch64 实现 ILP32 时的 [Patch]([gcc.gnu.org Git - gcc.git/search](https://gcc.gnu.org/git/?p=gcc.git&a=search&h=HEAD&st=commit&s=AArch64%2C+ILP32)) ，二者差异主要在于 AArch64 将默认指针扩展由Sign-Extend 转变为 Zero-Extend，而新32位沿用了 Sign-Extend。

```diff
// 新32位

Subject: [PATCH] Support RV64-ILP32
---
 gcc/config.gcc            |  3 +++
 gcc/config/riscv/elf.h    |  2 +-
 gcc/config/riscv/linux.h  |  2 +-
 gcc/config/riscv/riscv.cc |  4 ----
 gcc/config/riscv/riscv.h  | 12 ++++++++++--
 gcc/config/riscv/riscv.md |  8 ++++++--
 6 files changed, 21 insertions(+), 10 deletions(-)

diff --git a/gcc/config.gcc b/gcc/config.gcc
index f0958e1c959..1e7431189b9 100644
--- a/gcc/config.gcc
+++ b/gcc/config.gcc
@@ -4656,6 +4656,9 @@ case "${target}" in
 		ilp32,rv32* | ilp32e,rv32e* \
 		| ilp32f,rv32*f* | ilp32f,rv32g* \
 		| ilp32d,rv32*d* | ilp32d,rv32g* \
+		| ilp32f,rv64*f* | ilp32f,rv64g* \
+		| ilp32d,rv64*d* | ilp32d,rv64g* \
+		| ilp32,rv64* \                           
 		| lp64,rv64* \
 		| lp64f,rv64*f* | lp64f,rv64g* \
 		| lp64d,rv64*d* | lp64d,rv64g*)
// 使configure文件在configuration时通过--with-arch=rv64* --with-abi=ilp32*

diff --git a/gcc/config/riscv/elf.h b/gcc/config/riscv/elf.h
index a725c00b637..bea531ebe89 100644
--- a/gcc/config/riscv/elf.h
+++ b/gcc/config/riscv/elf.h
@@ -18,7 +18,7 @@ along with GCC; see the file COPYING3.  If not see
 <http://www.gnu.org/licenses/>.  */
 
 #define LINK_SPEC "\
--melf" XLEN_SPEC DEFAULT_ENDIAN_SPEC "riscv \
+-melf" ABI_LEN_SPEC DEFAULT_ENDIAN_SPEC "riscv \
 %{mno-relax:--no-relax} \
 %{mbig-endian:-EB} \
 %{mlittle-endian:-EL} \
// 在使用newlib库LINK时，新32位应该链接ELF32而非ELF64，即-melf32lriscv，原因为新32位生成的是32位elf文件

diff --git a/gcc/config/riscv/linux.h b/gcc/config/riscv/linux.h
index b9557a75dc7..4f33c88ef6e 100644
--- a/gcc/config/riscv/linux.h
+++ b/gcc/config/riscv/linux.h
@@ -58,7 +58,7 @@ along with GCC; see the file COPYING3.  If not see
   "%{mabi=ilp32:_ilp32}"
 
 #define LINK_SPEC "\
--melf" XLEN_SPEC DEFAULT_ENDIAN_SPEC "riscv" LD_EMUL_SUFFIX " \
+-melf" ABI_LEN_SPEC DEFAULT_ENDIAN_SPEC "riscv" LD_EMUL_SUFFIX " \
 %{mno-relax:--no-relax} \
 %{mbig-endian:-EB} \
 %{mlittle-endian:-EL} \
// 同上，使用glibc库LINK时，新32位应该链接ELF32而非ELF64,暂未添加musl库支持，musl，uclibc等c库支持将在将来视情况而定。

diff --git a/gcc/config/riscv/riscv.cc b/gcc/config/riscv/riscv.cc
index 3b7804b7501..ff61480f186 100644
--- a/gcc/config/riscv/riscv.cc
+++ b/gcc/config/riscv/riscv.cc
@@ -6085,10 +6085,6 @@ riscv_option_override (void)
       && riscv_abi != ABI_LP64 && riscv_abi != ABI_ILP32E)
     error ("z*inx requires ABI ilp32, ilp32e or lp64");
 
-  /* We do not yet support ILP32 on RV64.  */
-  if (BITS_PER_WORD != POINTER_SIZE)
-    error ("ABI requires %<-march=rv%d%>", POINTER_SIZE);
-
// 此处取消关于ABI与ISA的检查

   /* Validate -mpreferred-stack-boundary= value.  */
   riscv_stack_boundary = ABI_STACK_BOUNDARY;
   if (riscv_preferred_stack_boundary_arg)


diff --git a/gcc/config/riscv/riscv.h b/gcc/config/riscv/riscv.h
index faffd5a77fe..c9483b35a7b 100644
--- a/gcc/config/riscv/riscv.h
+++ b/gcc/config/riscv/riscv.h
@@ -77,6 +77,10 @@ extern const char *riscv_multi_lib_check (int argc, const char **argv);
 #define TARGET_64BIT           (__riscv_xlen == 64)
 #endif /* IN_LIBGCC2 */
 
+#ifndef TARGET_ILP32
+#define TARGET_ILP32           (riscv_abi <= ABI_ILP32D)
+#endif /*TARGET_ILP32*/
+
// 新增TARGET_ILP32用于区别rv64 lp64和新32位

#ifdef HAVE_AS_MISA_SPEC
 #define ASM_MISA_SPEC "%{misa-spec=*}"
 #else
@@ -172,7 +176,7 @@ ASM_MISA_SPEC
 #define SHORT_TYPE_SIZE 16
 #define INT_TYPE_SIZE 32
 #define LONG_LONG_TYPE_SIZE 64
-#define POINTER_SIZE (riscv_abi >= ABI_LP64 ? 64 : 32)
+#define POINTER_SIZE (TARGET_ILP32 ? 32 : 64)
 #define LONG_TYPE_SIZE POINTER_SIZE
// 当使用新32位和32位时，POINTER_SIZE为32

 #define FLOAT_TYPE_SIZE 32
@@ -792,7 +796,7 @@ typedef struct {
    After generation of rtl, the compiler makes no further distinction
    between pointers and any other objects of this machine mode.  */
 
-#define Pmode word_mode
+#define Pmode (TARGET_ILP32 ? SImode : DImode)
// Pointer mode在新32位下设置为SImode，与POINTER_SIZE保持一致 
 
 /* Give call MEMs SImode since it is the "most permissive" mode
    for both 32-bit and 64-bit targets.  */
@@ -1040,6 +1044,10 @@ extern poly_int64 riscv_v_adjust_nunits (enum machine_mode, int);
   "%{march=rv32*:32}" \
   "%{march=rv64*:64}" \
 
+#define ABI_LEN_SPEC \
+  "%{mabi=ilp32*:32}" \
+  "%{mabi=lp64*:64}" \
+
// 在定义LINK时使用，如前所述


 #define ABI_SPEC \
   "%{mabi=ilp32:ilp32}" \
   "%{mabi=ilp32e:ilp32e}" \


diff --git a/gcc/config/riscv/riscv.md b/gcc/config/riscv/riscv.md
index c8adc5af5d2..6129d4df8c5 100644
--- a/gcc/config/riscv/riscv.md
+++ b/gcc/config/riscv/riscv.md
@@ -2722,6 +2722,10 @@
   "reload_completed"
   [(const_int 0)]
 {
+  if (GET_MODE (operands[0]) != Pmode)
+    operands[0] = convert_to_mode (Pmode, operands[0], 0);    
+  if (GET_MODE (operands[1]) != Pmode)
+    operands[1] = convert_to_mode (Pmode, operands[1], 0);
   riscv_set_return_address (operands[0], operands[1]);
   DONE;
 })
// 默认情况下，该模版使用的是DImode，而新32位使用的address为32位，故而转成SImode

@@ -2931,8 +2935,8 @@
 
 (define_insn "stack_tie<mode>"
   [(set (mem:BLK (scratch))
-	(unspec:BLK [(match_operand:X 0 "register_operand" "r")
-		     (match_operand:X 1 "register_operand" "r")]
+	(unspec:BLK [(match_operand:P 0 "register_operand" "r")
+		     (match_operand:P 1 "register_operand" "r")]
 		    UNSPEC_TIE))]
   ""
   ""
// 将寄存器类型转为Pmode，因为调用stack_tie模版时传入指针为32位，X为DImode，与参数不符，故更改
-- 
2.41.0

```

## Binutils 与 gdb Patch Description

因 Binutils 与 GDB 均依赖 BFD 库，将两者的 Patch 放到此处

```diff
// 新32位，Patch 1
Subject: [PATCH 1/4] Remove checking when -march=rv64XX and -mabi=ilp32X
---
 gas/config/tc-riscv.c                            | 2 +-
 gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.d | 3 ---
 gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.l | 2 --
 3 files changed, 1 insertion(+), 6 deletions(-)
 delete mode 100644 gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.d
 delete mode 100644 gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.l

diff --git a/gas/config/tc-riscv.c b/gas/config/tc-riscv.c
index 0cc2484b04..99903decce 100644
--- a/gas/config/tc-riscv.c
+++ b/gas/config/tc-riscv.c
@@ -379,7 +379,7 @@ riscv_set_abi_by_arch (void)
       gas_assert (abi_xlen != 0 && xlen != 0 && float_abi != FLOAT_ABI_DEFAULT);
       if (abi_xlen > xlen)
 	as_bad ("can't have %d-bit ABI on %d-bit ISA", abi_xlen, xlen);
-      else if (abi_xlen < xlen)
+      else if (abi_xlen < xlen && (abi_xlen != 32 && xlen != 64))
// 取消as对传入参数 -march=rv64* -mabi=ilp32* 的报错

 	as_bad ("%d-bit ABI not yet supported on %d-bit ISA", abi_xlen, xlen);

       if (riscv_subset_supports (&riscv_rps_as, "e") && !rve_abi)
diff --git a/gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.d b/gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.d
deleted file mode 100644
index e3155f4895..0000000000
--- a/gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.d
+++ /dev/null
@@ -1,3 +0,0 @@
-#as: -march-attr -mabi=ilp32
-#source: mabi-attr-rv64iq.s
-#error_output: mabi-fail-rv64iq-ilp32.l
diff --git a/gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.l b/gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.l
deleted file mode 100644
index 8d45a07fd3..0000000000
--- a/gas/testsuite/gas/riscv/mabi-fail-rv64iq-ilp32.l
+++ /dev/null
@@ -1,2 +0,0 @@
-.*Assembler messages:
-.*Error: 32-bit ABI not yet supported on 64-bit ISA
-- 
// 删除相关测试用例

2.41.0

// Patch 2 此Patch在BFD和AS中支持新32位

Subject: [PATCH 2/4] Add support for rv64 arch using ilp32 abi
---
 bfd/archures.c        |  1 +
 bfd/bfd-in2.h         |  1 +
 bfd/cpu-riscv.c       |  2 ++
 bfd/elfnn-riscv.c     | 33 ++++++++++++++++++++++-----------
 binutils/readelf.c    |  3 +++
 gas/config/tc-riscv.c | 21 +++++++++++++++++----
 include/elf/riscv.h   |  3 +++
 7 files changed, 49 insertions(+), 15 deletions(-)

diff --git a/bfd/archures.c b/bfd/archures.c
index 6fe8701b412..fb3554d253a 100644
--- a/bfd/archures.c
+++ b/bfd/archures.c
@@ -447,6 +447,7 @@ DESCRIPTION
 .  bfd_arch_riscv,
 .#define bfd_mach_riscv32	132
 .#define bfd_mach_riscv64	164
+.#define bfd_mach_riscv64x32	16432
 .  bfd_arch_rl78,
 .#define bfd_mach_rl78		0x75
 .  bfd_arch_rx,	       {* Renesas RX.  *}
diff --git a/bfd/bfd-in2.h b/bfd/bfd-in2.h
index 7be18db20a8..c0615d3aeed 100644
--- a/bfd/bfd-in2.h
+++ b/bfd/bfd-in2.h
@@ -1700,6 +1700,7 @@ enum bfd_architecture
   bfd_arch_riscv,
 #define bfd_mach_riscv32       132
 #define bfd_mach_riscv64       164
+#define bfd_mach_riscv64x32    16432
   bfd_arch_rl78,
 #define bfd_mach_rl78          0x75
   bfd_arch_rx,        /* Renesas RX.  */

// 上两处添加新的bfd_arch,用于区别riscv64 lp64和新32位

diff --git a/bfd/cpu-riscv.c b/bfd/cpu-riscv.c
index a478797da69..38b7eb4a7b5 100644
--- a/bfd/cpu-riscv.c
+++ b/bfd/cpu-riscv.c
@@ -86,6 +86,7 @@ riscv_scan (const struct bfd_arch_info *info, const char *string)
 enum
 {
   I_riscv64,
+  I_riscv64x32,
   I_riscv32
 };
 
@@ -96,6 +97,7 @@ enum
 static const bfd_arch_info_type arch_info_struct[] =
 {
   N (64, bfd_mach_riscv64, "riscv:rv64", false, NN (I_riscv64)),
+  N (32, bfd_mach_riscv64x32, "riscv:rv64", false, NN (I_riscv64x32)),
   N (32, bfd_mach_riscv32, "riscv:rv32", false, NULL)
 };
// 用上文定义的bfd_arch_riscv64x32设置bfd_arch_info_type，32表示word和address位宽。此处mips n32，和x64_32与AArch64 ilp32存在差异，mips n32设置word为64，address为32，x64_32均设置为64，AArch64 ilp32均设置为32，此处沿用AArch64的设置。

diff --git a/bfd/elfnn-riscv.c b/bfd/elfnn-riscv.c
index a23b91ac15c..f1f72e9bd35 100644
--- a/bfd/elfnn-riscv.c
+++ b/bfd/elfnn-riscv.c
@@ -122,6 +122,11 @@
 
 #define RISCV_ELF_WORD_BYTES (1 << RISCV_ELF_LOG_WORD_BYTES)
 
+#define ABI_X32_P(abfd) \
+  ((elf_elfheader (abfd)->e_flags & EF_RISCV_X32) != 0)
+
+static bool ABI_X32 = false;
+
// 在bfd中，当as中使用新32位时，会设置e_flag中的EF_RISCV_X32，若EF_RISCV_X32为真，则将bfd_arch设置为bfd_mach_riscv64x32

 /* The name of the dynamic interpreter.  This is put in the .interp
    section.  */
 
@@ -1721,7 +1726,7 @@ perform_relocation (const reloc_howto_type *howto,
     case R_RISCV_GOT_HI20:
     case R_RISCV_TLS_GOT_HI20:
     case R_RISCV_TLS_GD_HI20:
-      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
+      if ((ARCH_SIZE > 32 || ABI_X32_P(input_bfd)) && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
 	return bfd_reloc_overflow;
       value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value));
       break;
@@ -1744,7 +1749,7 @@ perform_relocation (const reloc_howto_type *howto,
 
     case R_RISCV_CALL:
     case R_RISCV_CALL_PLT:
-      if (ARCH_SIZE > 32 && !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
+      if ((ARCH_SIZE > 32 || ABI_X32_P(input_bfd))&& !VALID_UTYPE_IMM (RISCV_CONST_HIGH_PART (value)))
 	return bfd_reloc_overflow;
       value = ENCODE_UTYPE_IMM (RISCV_CONST_HIGH_PART (value))
 	      | (ENCODE_ITYPE_IMM (value) << 32);
@@ -3685,7 +3690,7 @@ riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
     return NULL;
// 设置部分relocation与rv64 lp64保持一致

   /* Checking XLEN.  */
-  if (xlen_out != xlen_in)
+  if (xlen_out != xlen_in && !ABI_X32_P(ibfd))
     {
       _bfd_error_handler
 	(_("error: %pB: ISA string of input (%s) doesn't match "
@@ -3705,7 +3710,7 @@ riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
   if (!riscv_merge_multi_letter_ext (&in, &out))
     return NULL;
 
-  if (xlen_in != xlen_out)
+  if (xlen_in != xlen_out && !ABI_X32_P(ibfd))
     {
       _bfd_error_handler
 	(_("error: %pB: XLEN of input (%u) doesn't match "
@@ -3713,7 +3718,7 @@ riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
       return NULL;
     }
 
-  if (xlen_in != ARCH_SIZE)
+  if (xlen_in != ARCH_SIZE && !ABI_X32_P(ibfd))
     {
       _bfd_error_handler
 	(_("error: %pB: unsupported XLEN (%u), you might be "
@@ -3721,7 +3726,7 @@ riscv_merge_arch_attr_info (bfd *ibfd, char *in_arch, char *out_arch)
       return NULL;
     }
 
-  merged_arch_str = riscv_arch_str (ARCH_SIZE, &merged_subsets);
+  merged_arch_str = riscv_arch_str (xlen_in, &merged_subsets);
// 取消新32位合并bfd时对xlen和ARCH_SIZE的相等关系检查

   /* Release the subset lists.  */
   riscv_release_subset_list (&in_subsets);
@@ -3992,6 +3997,9 @@ _bfd_riscv_elf_merge_private_bfd_data (bfd *ibfd, struct bfd_link_info *info)
   /* Allow linking TSO and non-TSO, and keep the TSO flag.  */
   elf_elfheader (obfd)->e_flags |= new_flags & EF_RISCV_TSO;
 
+  /* Allow linking X32 and non-X32, and keep the X32 flag.  */
+  elf_elfheader (obfd)->e_flags |= new_flags & EF_RISCV_X32;
+
   return true;

// 设置e_flag EF_RISCV_X32


  fail:
@@ -4431,7 +4439,7 @@ _bfd_riscv_relax_call (bfd *abfd, asection *sec, asection *sym_sec,
   rvc = rvc && VALID_CJTYPE_IMM (foff);
 
   /* C.J exists on RV32 and RV64, but C.JAL is RV32-only.  */
-  rvc = rvc && (rd == 0 || (rd == X_RA && ARCH_SIZE == 32));
+  rvc = rvc && (rd == 0 || (rd == X_RA && ARCH_SIZE == 32 && !ABI_X32_P(abfd)));

   if (rvc)
     {
       /* Relax to C.J[AL] rd, addr.  */
       r_type = R_RISCV_RVC_JUMP;
-      auipc = rd == 0 ? MATCH_C_J : MATCH_C_JAL;
+      auipc = (rd == 0 || ABI_X32_P(abfd)) ? MATCH_C_J : MATCH_C_JAL;
       len = 2;
     }
   else if (VALID_JTYPE_IMM (foff))
// 不使用C.JAL

@@ -5140,7 +5148,7 @@ _bfd_riscv_relax_section (bfd *abfd, asection *sec,
   return ret;
 }
 
-#if ARCH_SIZE == 32
+#if ARCH_SIZE == 32 && !ABI_X32
 # define PRSTATUS_SIZE			204
 # define PRSTATUS_OFFSET_PR_CURSIG	12
 # define PRSTATUS_OFFSET_PR_PID		24
// 设置PRSTATIS与rv64相同

@@ -5310,9 +5318,12 @@ riscv_elf_grok_psinfo (bfd *abfd, Elf_Internal_Note *note)
 static bool
 riscv_elf_object_p (bfd *abfd)
 {
-  /* There are only two mach types in RISCV currently.  */
-  if (strcmp (abfd->xvec->name, "elf32-littleriscv") == 0
-      || strcmp (abfd->xvec->name, "elf32-bigriscv") == 0)
+  ABI_X32 = ABI_X32_P(abfd);
+  /* There are only three mach types in RISCV currently.  */
+  if (ABI_X32)
+    bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv64x32);
+  else if (strcmp (abfd->xvec->name, "elf32-littleriscv") == 0
+      	|| strcmp (abfd->xvec->name, "elf32-bigriscv") == 0)
     bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv32);
   else
     bfd_default_set_arch_mach (abfd, bfd_arch_riscv, bfd_mach_riscv64);
// 当使用新32位时，bfd_set_arch为bfd_mach_riscv64x32

diff --git a/binutils/readelf.c b/binutils/readelf.c
index b872876a8b6..5e3378457c7 100644
--- a/binutils/readelf.c
+++ b/binutils/readelf.c
@@ -4119,6 +4119,9 @@ get_machine_flags (Filedata * filedata, unsigned e_flags, unsigned e_machine)
 	  if (e_flags & EF_RISCV_TSO)
 	    strcat (buf, ", TSO");
 
+	  if (e_flags & EF_RISCV_X32)
+	    strcat (buf, ", X32");
+
// readelf中增加对X32 flag的识别

 	  switch (e_flags & EF_RISCV_FLOAT_ABI)
 	    {
 	    case EF_RISCV_FLOAT_ABI_SOFT:
diff --git a/gas/config/tc-riscv.c b/gas/config/tc-riscv.c
index 99903deccec..7c47530801e 100644
--- a/gas/config/tc-riscv.c
+++ b/gas/config/tc-riscv.c
@@ -278,6 +278,14 @@ riscv_set_tso (void)
   elf_flags |= EF_RISCV_TSO;
 }
 
+/* Turn on the x32 flag for elf_flags once we have enabled x32 model.  */
+
+static void
+riscv_set_x32 (void)
+{
+  elf_flags |= EF_RISCV_X32;
+}
+


 /* The linked list hanging off of .subsets_list records all enabled extensions,
    which are parsed from the architecture string.  The architecture string can
    be set by the -march option, the elf architecture attributes, and the
@@ -405,6 +413,9 @@ riscv_set_abi_by_arch (void)
 
   if (rve_abi)
     elf_flags |= EF_RISCV_RVE;
+
+  if (abi_xlen == 32 && xlen == 64)
+    riscv_set_x32 ();
 }
// AS中，当使用新32位时，在elf_flag中添加EF_RISCV_X32 


 /* Handle of the OPCODE hash table.  */
@@ -706,9 +717,9 @@ const char *
 riscv_target_format (void)
 {
   if (target_big_endian)
-    return xlen == 64 ? "elf64-bigriscv" : "elf32-bigriscv";
+    return abi_xlen == 64 ? "elf64-bigriscv" : "elf32-bigriscv";
   else
-    return xlen == 64 ? "elf64-littleriscv" : "elf32-littleriscv";
+    return abi_xlen == 64 ? "elf64-littleriscv" : "elf32-littleriscv";
 }
 
 /* Return the length of instruction INSN.  */
@@ -1505,7 +1516,8 @@ init_opcode_hash (const struct riscv_opcode *opcodes,
 void
 md_begin (void)
 {
-  unsigned long mach = xlen == 64 ? bfd_mach_riscv64 : bfd_mach_riscv32;
+  unsigned long mach = xlen == 64 ? 
+      (abi_xlen == 32 ? bfd_mach_riscv64x32 : bfd_mach_riscv64) : bfd_mach_riscv32;
 
   if (! bfd_set_arch_mach (stdoutput, bfd_arch_riscv, mach))
     as_warn (_("could not set architecture and machine"));
@@ -4912,7 +4924,8 @@ s_riscv_attribute (int ignored ATTRIBUTE_UNUSED)
       if (old_xlen != xlen)
 	{
 	  /* We must re-init bfd again if xlen is changed.  */
-	  unsigned long mach = xlen == 64 ? bfd_mach_riscv64 : bfd_mach_riscv32;
+	  unsigned long mach = xlen == 64 ? (abi_xlen == 32 ? 
+        bfd_mach_riscv64x32 : bfd_mach_riscv64) : bfd_mach_riscv32;
 	  bfd_find_target (riscv_target_format (), stdoutput);
// 设置当使用新32位时，AS生成的elf文件为32位

 	  if (! bfd_set_arch_mach (stdoutput, bfd_arch_riscv, mach))
diff --git a/include/elf/riscv.h b/include/elf/riscv.h
index aabc71cf979..932ce42bf97 100644
--- a/include/elf/riscv.h
+++ b/include/elf/riscv.h
@@ -124,6 +124,9 @@ END_RELOC_NUMBERS (R_RISCV_max)
 /* File uses the TSO model. */
 #define EF_RISCV_TSO 0x0010
 
+/* File uses the X32 model. */
+#define EF_RISCV_X32 0x0020
+
// 设置X32 flag bit位，目前设置的为0x0020，等合入上游时会在psABI会议讨论具体的flag位

 /* Additional section types.  */
 #define SHT_RISCV_ATTRIBUTES 0x70000003 /* Section holds attributes.  */

// Patch3 ，提供反汇编支持

Subject: [PATCH 3/4] Add rv64 ilp32 support in disassemble
---
 opcodes/riscv-dis.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/opcodes/riscv-dis.c b/opcodes/riscv-dis.c
index f25993d1e4..550cabf875 100644
--- a/opcodes/riscv-dis.c
+++ b/opcodes/riscv-dis.c
@@ -263,7 +263,7 @@ print_insn_args (const char *oparg, insn_t l, bfd_vma pc, disassemble_info *info
 	    case 'j':
 	      if (((l & MASK_C_ADDI) == MATCH_C_ADDI) && rd != 0)
 		maybe_print_address (pd, rd, EXTRACT_CITYPE_IMM (l), 0);
-	      if (info->mach == bfd_mach_riscv64
+	      if ((info->mach == bfd_mach_riscv64 || info->mach == bfd_mach_riscv64x32)
 		  && ((l & MASK_C_ADDIW) == MATCH_C_ADDIW) && rd != 0)
 		maybe_print_address (pd, rd, EXTRACT_CITYPE_IMM (l), 1);
 	      print (info->stream, dis_style_immediate, "%d",
@@ -463,7 +463,7 @@ print_insn_args (const char *oparg, insn_t l, bfd_vma pc, disassemble_info *info
 	  if (((l & MASK_ADDI) == MATCH_ADDI && rs1 != 0)
 	      || (l & MASK_JALR) == MATCH_JALR)
 	    maybe_print_address (pd, rs1, EXTRACT_ITYPE_IMM (l), 0);
-	  if (info->mach == bfd_mach_riscv64
+	  if ((info->mach == bfd_mach_riscv64 || info->mach == bfd_mach_riscv64x32)
 	      && ((l & MASK_ADDIW) == MATCH_ADDIW) && rs1 != 0)
 	    maybe_print_address (pd, rs1, EXTRACT_ITYPE_IMM (l), 1);
 	  print (info->stream, dis_style_immediate, "%d",
@@ -724,7 +724,7 @@ riscv_disassemble_insn (bfd_vma memaddr,
   if (op != NULL)
     {
       /* If XLEN is not known, get its value from the ELF class.  */
-      if (info->mach == bfd_mach_riscv64)
+      if (info->mach == bfd_mach_riscv64 || info->mach == bfd_mach_riscv64x32)
 	xlen = 64;
       else if (info->mach == bfd_mach_riscv32)
 	xlen = 32;
-- 

//Patch4，增加对GDB的实验性支持
Subject: [PATCH 4/4] Add rv64 ilp32 support in gdb
---
 gdb/arch/riscv.h | 10 +++++++++-
 gdb/riscv-tdep.c | 20 ++++++++++++++++----
 2 files changed, 25 insertions(+), 5 deletions(-)

diff --git a/gdb/arch/riscv.h b/gdb/arch/riscv.h
index 54610ed6c16..a41faba1168 100644
--- a/gdb/arch/riscv.h
+++ b/gdb/arch/riscv.h
@@ -41,6 +41,12 @@ struct riscv_gdbarch_features
      uninitialised.  */
   int xlen = 0;
 
+  /* The size of the pointer_size in bytes.  This is either 4 (ILP32), 8
+     (LP64).  No other value is valid.  Initialise to the
+     invalid 0 value so we can spot if one of these is used
+     uninitialised.  */
+  int abi_xlen = 0;
+
   /* The size of the f-registers in bytes.  This is either 4 (RV32), 8
      (RV64), or 16 (RV128).  This can also hold the value 0 to indicate
      that there are no f-registers.  No other value is valid.  */
@@ -68,6 +74,7 @@ struct riscv_gdbarch_features
   bool operator== (const struct riscv_gdbarch_features &rhs) const
   {
     return (xlen == rhs.xlen && flen == rhs.flen
+	    && abi_xlen == rhs.abi_xlen
 	    && embedded == rhs.embedded && vlen == rhs.vlen
 	    && has_fflags_reg == rhs.has_fflags_reg
 	    && has_frm_reg == rhs.has_frm_reg
@@ -88,8 +95,9 @@ struct riscv_gdbarch_features
 		       | (has_frm_reg ? 1 : 0) << 12
 		       | (has_fcsr_reg ? 1 : 0) << 13
 		       | (xlen & 0x1f) << 5
+		       | (abi_xlen & 0x1f) << 14
 		       | (flen & 0x1f) << 0
-		       | (vlen & 0xfff) << 14);
+		       | (vlen & 0xfff) << 19);
     return val;
   }
 };
diff --git a/gdb/riscv-tdep.c b/gdb/riscv-tdep.c
index 500279e1ae9..d4531896cc1 100644
--- a/gdb/riscv-tdep.c
+++ b/gdb/riscv-tdep.c
@@ -774,7 +774,7 @@ int
 riscv_abi_xlen (struct gdbarch *gdbarch)
 {
   riscv_gdbarch_tdep *tdep = gdbarch_tdep<riscv_gdbarch_tdep> (gdbarch);
-  return tdep->abi_features.xlen;
+  return tdep->abi_features.abi_xlen;
 }
 
 /* See riscv-tdep.h.  */
@@ -3835,9 +3835,15 @@ riscv_features_from_bfd (const bfd *abfd)
       int e_flags = elf_elfheader (abfd)->e_flags;
 
       if (eclass == ELFCLASS32)
-	features.xlen = 4;
+	{
+	  features.xlen == 4;
+    features.abi_xlen = 4;
+	}
       else if (eclass == ELFCLASS64)
-	features.xlen = 8;
+	{
+	  features.xlen == 8;
+    features.abi_xlen = 8;
+	}
       else
 	internal_error (_("unknown ELF header class %d"), eclass);
 
@@ -3846,6 +3852,12 @@ riscv_features_from_bfd (const bfd *abfd)
       else if (e_flags & EF_RISCV_FLOAT_ABI_SINGLE)
 	features.flen = 4;
 
+      if (e_flags & EF_RISCV_X32)
+	{
+	  features.xlen == 8;
+    features.abi_xlen = 4;
+	}
+
       if (e_flags & EF_RISCV_RVE)
 	{
 	  if (features.xlen == 8)
@@ -4175,7 +4187,7 @@ riscv_gdbarch_init (struct gdbarch_info info,
   /* Target data types.  */
   set_gdbarch_short_bit (gdbarch, 16);
   set_gdbarch_int_bit (gdbarch, 32);
-  set_gdbarch_long_bit (gdbarch, riscv_isa_xlen (gdbarch) * 8);
+  set_gdbarch_long_bit (gdbarch, riscv_abi_xlen (gdbarch) * 8);
   set_gdbarch_long_long_bit (gdbarch, 64);
   set_gdbarch_float_bit (gdbarch, 32);
   set_gdbarch_double_bit (gdbarch, 64);
-- 
2.34.1



```

## Glibc Patch Description

增加了Glibc上的相关支持，做法是将新32位导向rv32 ilp32

```diff
Subject: [PATCH] Support ilp32 on rv64

---
 config.h.in                                  |  3 +++
 sysdeps/riscv/bits/wordsize.h                |  6 ++++--
 sysdeps/riscv/jmpbuf-unwind.h                |  2 +-
 sysdeps/riscv/preconfigure                   | 18 ++++++++++++++++--
 sysdeps/riscv/preconfigure.ac                | 16 ++++++++++++++--
 sysdeps/riscv/sfp-machine.h                  |  2 +-
 sysdeps/riscv/sys/asm.h                      |  4 ++--
 sysdeps/unix/sysv/linux/riscv/bits/procfs.h  | 12 +++++++++---
 sysdeps/unix/sysv/linux/riscv/shlib-versions | 14 ++++++++++----
 9 files changed, 60 insertions(+), 17 deletions(-)

diff --git a/config.h.in b/config.h.in
index 09730d9d52..6851c1fdaa 100644
--- a/config.h.in
+++ b/config.h.in
@@ -129,6 +129,9 @@
 /* C-SKY floating-point ABI.  */
 #undef CSKY_HARD_FLOAT_ABI
 
+/* RISC-V ISA ABI for ld.so.  */
+#undef RISCV_ISA_XLEN
+
// 新增ISA XLEN用以区分rv32和rv64，原ABI_XLEN用来表示Pointer Size

 /* RISC-V integer ABI for ld.so.  */
 #undef RISCV_ABI_XLEN
 
diff --git a/sysdeps/riscv/bits/wordsize.h b/sysdeps/riscv/bits/wordsize.h
index 47593431ab..61c2eb95b3 100644
--- a/sysdeps/riscv/bits/wordsize.h
+++ b/sysdeps/riscv/bits/wordsize.h
@@ -16,8 +16,10 @@
    License along with the GNU C Library.  If not, see
    <https://www.gnu.org/licenses/>.  */
 
-#if __riscv_xlen == (__SIZEOF_POINTER__ * 8)
-# define __WORDSIZE __riscv_xlen
+#if (__SIZEOF_POINTER__) == 4
+#define __WORDSIZE 32
+#elif (__SIZEOF_POINTER__) == 8
+#define __WORDSIZE 64
 #else
 # error unsupported ABI
 #endif
// 新32位使用 wordsize 32 
 
diff --git a/sysdeps/riscv/jmpbuf-unwind.h b/sysdeps/riscv/jmpbuf-unwind.h
index c35e90d889..f7566c6af6 100644
--- a/sysdeps/riscv/jmpbuf-unwind.h
+++ b/sysdeps/riscv/jmpbuf-unwind.h
@@ -28,7 +28,7 @@
   ((void *) (address) < (void *) demangle ((jmpbuf)[0].__sp))
 
 #define _JMPBUF_CFA_UNWINDS_ADJ(_jmpbuf, _context, _adj) \
-  _JMPBUF_UNWINDS_ADJ (_jmpbuf, (void *) _Unwind_GetCFA (_context), _adj)
+  _JMPBUF_UNWINDS_ADJ (_jmpbuf, (void *) (uintptr_t) _Unwind_GetCFA (_context), _adj)
// 此处增加新32位支持，否则会出现类型转换警告

 static inline uintptr_t __attribute__ ((unused))
 _jmpbuf_sp (__jmp_buf regs)
diff --git a/sysdeps/riscv/preconfigure b/sysdeps/riscv/preconfigure
index 4dedf4b0bb..ecfcab0a16 100644
--- a/sysdeps/riscv/preconfigure
+++ b/sysdeps/riscv/preconfigure
@@ -4,6 +4,7 @@
 case "$machine" in
 riscv*)
     xlen=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __riscv_xlen \(.*\)/\1/p'`
+    abi_xlen=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __SIZEOF_LONG__ \(.*\)/\1/p'`
     flen=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __riscv_flen \(.*\)/\1/p'`
     float_abi=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __riscv_float_abi_\([^ ]*\) .*/\1/p'`
     atomic=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | grep '#define __riscv_atomic' | cut -d' ' -f2`
@@ -16,6 +17,15 @@ riscv*)
 	;;
     esac
 
+    case "$abi_xlen" in
+    4)
+    abi_xlen=32
+	;;
+    8)
+	abi_xlen=64
+	;;
+    esac
+
     case "$flen" in
     64)
 	float_machine=rvd
@@ -56,10 +66,14 @@ riscv*)
     esac
 
     base_machine=riscv
-    machine=riscv/rv$xlen/$float_machine
+    machine=riscv/rv$abi_xlen/$float_machine
+
+    cat >>confdefs.h <<_ACEOF
+#define RISCV_ISA_XLEN $xlen
+_ACEOF
 
     cat >>confdefs.h <<_ACEOF
-#define RISCV_ABI_XLEN $xlen
+#define RISCV_ABI_XLEN $abi_xlen
 _ACEOF
 
     cat >>confdefs.h <<_ACEOF
diff --git a/sysdeps/riscv/preconfigure.ac b/sysdeps/riscv/preconfigure.ac
index a5c30e0dbf..5cec485877 100644
--- a/sysdeps/riscv/preconfigure.ac
+++ b/sysdeps/riscv/preconfigure.ac
@@ -4,6 +4,7 @@ GLIBC_PROVIDES[]dnl See aclocal.m4 in the top level source directory.
 case "$machine" in
 riscv*)
     xlen=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __riscv_xlen \(.*\)/\1/p'`
+    abi_xlen=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __SIZEOF_LONG__ \(.*\)/\1/p'`
     flen=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __riscv_flen \(.*\)/\1/p'`
     float_abi=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | sed -n 's/^#define __riscv_float_abi_\([^ ]*\) .*/\1/p'`
     atomic=`$CC $CFLAGS $CPPFLAGS -E -dM -xc /dev/null | grep '#define __riscv_atomic' | cut -d' ' -f2`
@@ -16,6 +17,16 @@ riscv*)
 	;;
     esac
 
+     case "$abi_xlen" in
+    4)
+    abi_xlen=32
+    ;;
+    8)
+    abi_xlen=64
+    ;;
+    esac
+
+
     case "$flen" in
     64)
 	float_machine=rvd
@@ -56,9 +67,10 @@ riscv*)
     esac
 
     base_machine=riscv
-    machine=riscv/rv$xlen/$float_machine
+    machine=riscv/rv$abi_xlen/$float_machine
 
-    AC_DEFINE_UNQUOTED([RISCV_ABI_XLEN], [$xlen])
+    AC_DEFINE_UNQUOTED([RISCV_ISA_XLEN], [$xlen])
+    AC_DEFINE_UNQUOTED([RISCV_ABI_XLEN], [$abi_xlen])
     AC_DEFINE_UNQUOTED([RISCV_ABI_FLEN], [$abi_flen])
     ;;
 esac
// 设置新32位preconfigure文件，定义ISA_XLEN和ABI_XLEN 

diff --git a/sysdeps/riscv/sys/asm.h b/sysdeps/riscv/sys/asm.h
index 5432f2d5d2..f727c24186 100644
--- a/sysdeps/riscv/sys/asm.h
+++ b/sysdeps/riscv/sys/asm.h
@@ -20,12 +20,12 @@
 #define _SYS_ASM_H
 
 /* Macros to handle different pointer/register sizes for 32/64-bit code.  */
-#if __riscv_xlen == 64
+#if (__SIZEOF_LONG__ * 8) == 64
 # define PTRLOG 3
 # define SZREG  8
 # define REG_S sd
 # define REG_L ld
-#elif __riscv_xlen == 32
+#elif (__SIZEOF_LONG__ * 8) == 32
 # define PTRLOG 2
 # define SZREG  4
 # define REG_S sw
// 仿照设置ptrlog szreg load、store 此处存疑

diff --git a/sysdeps/unix/sysv/linux/riscv/bits/procfs.h b/sysdeps/unix/sysv/linux/riscv/bits/procfs.h
index 3f8c11fee4..2cf2790aab 100644
--- a/sysdeps/unix/sysv/linux/riscv/bits/procfs.h
+++ b/sysdeps/unix/sysv/linux/riscv/bits/procfs.h
@@ -26,6 +26,12 @@
 #define ELF_NGREG	NGREG
 #define ELF_NFPREG	NFPREG
 
-typedef unsigned long int elf_greg_t;
-typedef unsigned long int elf_gregset_t[32];
-typedef union __riscv_mc_fp_state elf_fpregset_t;
+#if __riscv_xlen == 32
+   typedef unsigned long int elf_greg_t;
+   typedef unsigned long int elf_gregset_t[32];
+   typedef union __riscv_mc_fp_state elf_fpregset_t;
+#else
+   typedef unsigned long long int elf_greg_t;
+   typedef unsigned long long int elf_gregset_t[32];
+   typedef union __riscv_mc_fp_state elf_fpregset_t;
+#endif
\ No newline at end of file
diff --git a/sysdeps/unix/sysv/linux/riscv/shlib-versions b/sysdeps/unix/sysv/linux/riscv/shlib-versions
index e8a7be7313..8d5511ba87 100644
--- a/sysdeps/unix/sysv/linux/riscv/shlib-versions
+++ b/sysdeps/unix/sysv/linux/riscv/shlib-versions
@@ -1,13 +1,19 @@
-%if RISCV_ABI_XLEN == 64 && RISCV_ABI_FLEN == 64
+%if RISCV_ISA_XLEN == 64 && RISCV_ABI_XLEN == 64 && RISCV_ABI_FLEN == 64
 DEFAULT		GLIBC_2.27
 ld=ld-linux-riscv64-lp64d.so.1
-%elif RISCV_ABI_XLEN == 64 && RISCV_ABI_FLEN == 0
+%elif RISCV_ISA_XLEN == 64 && RISCV_ABI_XLEN == 64 && RISCV_ABI_FLEN == 0
 DEFAULT		GLIBC_2.27
 ld=ld-linux-riscv64-lp64.so.1
-%elif RISCV_ABI_XLEN == 32 && RISCV_ABI_FLEN == 64
+%elif RISCV_ISA_XLEN == 64 && RISCV_ABI_XLEN == 32 && RISCV_ABI_FLEN == 64
+DEFAULT		GLIBC_2.33
+ld=ld-linux-riscv64-ilp32d.so.1
+%elif RISCV_ISA_XLEN == 64 && RISCV_ABI_XLEN == 32 && RISCV_ABI_FLEN == 0
+DEFAULT		GLIBC_2.33
+ld=ld-linux-riscv64-ilp32.so.1
+%elif RISCV_ISA_XLEN == 32 && RISCV_ABI_XLEN == 32 && RISCV_ABI_FLEN == 64
 DEFAULT		GLIBC_2.33
 ld=ld-linux-riscv32-ilp32d.so.1
-%elif RISCV_ABI_XLEN == 32 && RISCV_ABI_FLEN == 0
+%elif RISCV_ISA_XLEN == 32 && RISCV_ABI_XLEN == 32 && RISCV_ABI_FLEN == 0
 DEFAULT		GLIBC_2.33
 ld=ld-linux-riscv32-ilp32.so.1
 %else

```

