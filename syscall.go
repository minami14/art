package art

import (
	"fmt"
	"syscall"
)

func (a *Art) Syscall(...string) error {
	rax, err := a.Get("RAX")
	if err != nil {
		return err
	}

	args, err := a.syscallArgs(6)
	if err != nil {
		return err
	}

	if a.UseHostKernel {
		r1, r2, _ := syscall.Syscall6(uintptr(rax), uintptr(args[0]), uintptr(args[1]), uintptr(args[2]), uintptr(args[3]), uintptr(args[4]), uintptr(args[5]))

		if err := a.Set("RAX", uint64(r1)); err != nil {
			return err
		}

		if err := a.Set("RDX", uint64(r2)); err != nil {
			return err
		}

		return nil
	}

	call, ok := a.SystemCalls[rax]
	if !ok {
		return fmt.Errorf("invalid syscall number: %v", rax)
	}

	return call()
}

func (a *Art) syscallArgs(n int) ([]uint64, error) {
	var args []uint64
	for _, r := range []string{"RDI", "RSI", "RDX", "R10", "R8", "R9"}[:n] {
		v, err := a.Get(r)
		if err != nil {
			return nil, err
		}
		args = append(args, v)
	}

	return args, nil
}

func setSyscallLinux(a *Art) {
	a.SystemCalls = map[uint64]func() error{
		0:   a.syscallRead,
		1:   a.syscallWrite,
		2:   a.syscallOpen,
		3:   a.syscallClose,
		4:   a.syscallStat,
		5:   a.syscallFstat,
		6:   a.syscallLstat,
		7:   a.syscallPoll,
		8:   a.syscallLseek,
		9:   a.syscallMmap,
		10:  a.syscallMprotect,
		11:  a.syscallMunmap,
		12:  a.syscallBrk,
		13:  a.syscallRtSigaction64,
		14:  a.syscallRtSigprocmask,
		15:  a.syscallRtSigreturn64,
		16:  a.syscallIoctl64,
		17:  a.syscallPread64,
		18:  a.syscallPwrite64,
		19:  a.syscallReadv64,
		20:  a.syscallWritev64,
		21:  a.syscallAccess,
		22:  a.syscallPipe,
		23:  a.syscallSelect,
		24:  a.syscallSchedYield,
		25:  a.syscallMremap,
		26:  a.syscallMsync,
		27:  a.syscallMincore,
		28:  a.syscallMadvise,
		29:  a.syscallShmget,
		30:  a.syscallShmat,
		31:  a.syscallShmctl,
		32:  a.syscallDup,
		33:  a.syscallDup2,
		34:  a.syscallPause,
		35:  a.syscallNanosleep,
		36:  a.syscallGetitimer,
		37:  a.syscallAlarm,
		38:  a.syscallSetitimer,
		39:  a.syscallGetpid,
		40:  a.syscallSendfile,
		41:  a.syscallSocket,
		42:  a.syscallConnect,
		43:  a.syscallAccept,
		44:  a.syscallSendto,
		45:  a.syscallRecvfrom64,
		46:  a.syscallSendmsg64,
		47:  a.syscallRecvmsg64,
		48:  a.syscallShutdown,
		49:  a.syscallBind,
		50:  a.syscallListen,
		51:  a.syscallGetsockname,
		52:  a.syscallGetpeername,
		53:  a.syscallSocketpair,
		54:  a.syscallSetsockopt64,
		55:  a.syscallGetsockopt64,
		56:  a.syscallClone,
		57:  a.syscallFork,
		58:  a.syscallVfork,
		59:  a.syscallExecve64,
		60:  a.syscallExit,
		61:  a.syscallWait4,
		62:  a.syscallKill,
		63:  a.syscallUname,
		64:  a.syscallSemget,
		65:  a.syscallSemop,
		66:  a.syscallSemctl,
		67:  a.syscallShmdt,
		68:  a.syscallMsgget,
		69:  a.syscallMsgsnd,
		70:  a.syscallMsgrcv,
		71:  a.syscallMsgctl,
		72:  a.syscallFcntl,
		73:  a.syscallFlock,
		74:  a.syscallFsync,
		75:  a.syscallFdatasync,
		76:  a.syscallTruncate,
		77:  a.syscallFtruncate,
		78:  a.syscallGetdents,
		79:  a.syscallGetcwd,
		80:  a.syscallChdir,
		81:  a.syscallFchdir,
		82:  a.syscallRename,
		83:  a.syscallMkdir,
		84:  a.syscallRmdir,
		85:  a.syscallCreat,
		86:  a.syscallLink,
		87:  a.syscallUnlink,
		88:  a.syscallSymlink,
		89:  a.syscallReadlink,
		90:  a.syscallChmod,
		91:  a.syscallFchmod,
		92:  a.syscallChown,
		93:  a.syscallFchown,
		94:  a.syscallLchown,
		95:  a.syscallUmask,
		96:  a.syscallGettimeofday,
		97:  a.syscallGetrlimit,
		98:  a.syscallGetrusage,
		99:  a.syscallSysinfo,
		100: a.syscallTimes,
		101: a.syscallPtrace64,
		102: a.syscallGetuid,
		103: a.syscallSyslog,
		104: a.syscallGetgid,
		105: a.syscallSetuid,
		106: a.syscallSetgid,
		107: a.syscallGeteuid,
		108: a.syscallGetegid,
		109: a.syscallSetpgid,
		110: a.syscallGetppid,
		111: a.syscallGetpgrp,
		112: a.syscallSetsid,
		113: a.syscallSetreuid,
		114: a.syscallSetregid,
		115: a.syscallGetgroups,
		116: a.syscallSetgroups,
		117: a.syscallSetresuid,
		118: a.syscallGetresuid,
		119: a.syscallSetresgid,
		120: a.syscallGetresgid,
		121: a.syscallGetpgid,
		122: a.syscallSetfsuid,
		123: a.syscallSetfsgid,
		124: a.syscallGetsid,
		125: a.syscallCapget,
		126: a.syscallCapset,
		127: a.syscallRtSigpending64,
		128: a.syscallRtSigtimedwait64,
		129: a.syscallRtSigqueueinfo64,
		130: a.syscallRtSigsuspend,
		131: a.syscallSigaltstack64,
		132: a.syscallUtime,
		133: a.syscallMknod,
		134: a.syscallUselib64,
		135: a.syscallPersonality,
		136: a.syscallUstat,
		137: a.syscallStatfs,
		138: a.syscallFstatfs,
		139: a.syscallSysfs,
		140: a.syscallGetpriority,
		141: a.syscallSetpriority,
		142: a.syscallSchedSetparam,
		143: a.syscallSchedGetparam,
		144: a.syscallSchedSetscheduler,
		145: a.syscallSchedGetscheduler,
		146: a.syscallSchedGetPriorityMax,
		147: a.syscallSchedGetPriorityMin,
		148: a.syscallSchedRrGetInterval,
		149: a.syscallMlock,
		150: a.syscallMunlock,
		151: a.syscallMlockall,
		152: a.syscallMunlockall,
		153: a.syscallVhangup,
		154: a.syscallModifyLdt,
		155: a.syscallPivotRoot,
		156: a.syscallSysctl64,
		157: a.syscallPrctl,
		158: a.syscallArchPrctl,
		159: a.syscallAdjtimex,
		160: a.syscallSetrlimit,
		161: a.syscallChroot,
		162: a.syscallSync,
		163: a.syscallAcct,
		164: a.syscallSettimeofday,
		165: a.syscallMount,
		166: a.syscallUmount2,
		167: a.syscallSwapon,
		168: a.syscallSwapoff,
		169: a.syscallReboot,
		170: a.syscallSethostname,
		171: a.syscallSetdomainname,
		172: a.syscallIopl,
		173: a.syscallIoperm,
		174: a.syscallCreateModule64,
		175: a.syscallInitModule,
		176: a.syscallDeleteModule,
		177: a.syscallGetKernelSyms64,
		178: a.syscallQueryModule64,
		179: a.syscallQuotactl,
		180: a.syscallNfsservctl64,
		181: a.syscallGetpmsg,
		182: a.syscallPutpmsg,
		183: a.syscallAfsSyscall,
		184: a.syscallTuxcall,
		185: a.syscallSecurity,
		186: a.syscallGettid,
		187: a.syscallReadahead,
		188: a.syscallSetxattr,
		189: a.syscallLsetxattr,
		190: a.syscallFsetxattr,
		191: a.syscallGetxattr,
		192: a.syscallLgetxattr,
		193: a.syscallFgetxattr,
		194: a.syscallListxattr,
		195: a.syscallLlistxattr,
		196: a.syscallFlistxattr,
		197: a.syscallRemovexattr,
		198: a.syscallLremovexattr,
		199: a.syscallFremovexattr,
		200: a.syscallTkill,
		201: a.syscallTime,
		202: a.syscallFutex,
		203: a.syscallSchedSetaffinity,
		204: a.syscallSchedGetaffinity,
		205: a.syscallSetThreadArea64,
		206: a.syscallIoSetup64,
		207: a.syscallIoDestroy,
		208: a.syscallIoGetevents,
		209: a.syscallIoSubmit64,
		210: a.syscallIoCancel,
		211: a.syscallGetThreadArea64,
		212: a.syscallLookupDcookie,
		213: a.syscallEpollCreate,
		214: a.syscallEpollCtlOld64,
		215: a.syscallEpollWaitOld64,
		216: a.syscallRemapFilePages,
		217: a.syscallGetdents64,
		218: a.syscallSetTidAddress,
		219: a.syscallRestartSyscall,
		220: a.syscallSemtimedop,
		221: a.syscallFadvise64,
		222: a.syscallTimerCreate64,
		223: a.syscallTimerSettime,
		224: a.syscallTimerGettime,
		225: a.syscallTimerGetoverrun,
		226: a.syscallTimerDelete,
		227: a.syscallClockSettime,
		228: a.syscallClockGettime,
		229: a.syscallClockGetres,
		230: a.syscallClockNanosleep,
		231: a.syscallExitGroup,
		232: a.syscallEpollWait,
		233: a.syscallEpollCtl,
		234: a.syscallTgkill,
		235: a.syscallUtimes,
		236: a.syscallVserver64,
		237: a.syscallMbind,
		238: a.syscallSetMempolicy,
		239: a.syscallGetMempolicy,
		240: a.syscallMqOpen,
		241: a.syscallMqUnlink,
		242: a.syscallMqTimedsend,
		243: a.syscallMqTimedreceive,
		244: a.syscallMqNotify64,
		245: a.syscallMqGetsetattr,
		246: a.syscallKexecLoad64,
		247: a.syscallWaitid64,
		248: a.syscallAddKey,
		249: a.syscallRequestKey,
		250: a.syscallKeyctl,
		251: a.syscallIoprioSet,
		252: a.syscallIoprioGet,
		253: a.syscallInotifyInit,
		254: a.syscallInotifyAddWatch,
		255: a.syscallInotifyRmWatch,
		256: a.syscallMigratePages,
		257: a.syscallOpenat,
		258: a.syscallMkdirat,
		259: a.syscallMknodat,
		260: a.syscallFchownat,
		261: a.syscallFutimesat,
		262: a.syscallNewfstatat,
		263: a.syscallUnlinkat,
		264: a.syscallRenameat,
		265: a.syscallLinkat,
		266: a.syscallSymlinkat,
		267: a.syscallReadlinkat,
		268: a.syscallFchmodat,
		269: a.syscallFaccessat,
		270: a.syscallPselect6,
		271: a.syscallPpoll,
		272: a.syscallUnshare,
		273: a.syscallSetRobustList64,
		274: a.syscallGetRobustList64,
		275: a.syscallSplice,
		276: a.syscallTee,
		277: a.syscallSyncFileRange,
		278: a.syscallVmsplice64,
		279: a.syscallMovePages64,
		280: a.syscallUtimensat,
		281: a.syscallEpollPwait,
		282: a.syscallSignalfd,
		283: a.syscallTimerfdCreate,
		284: a.syscallEventfd,
		285: a.syscallFallocate,
		286: a.syscallTimerfdSettime,
		287: a.syscallTimerfdGettime,
		288: a.syscallAccept4,
		289: a.syscallSignalfd4,
		290: a.syscallEventfd2,
		291: a.syscallEpollCreate1,
		292: a.syscallDup3,
		293: a.syscallPipe2,
		294: a.syscallInotifyInit1,
		295: a.syscallPreadv64,
		296: a.syscallPwritev64,
		297: a.syscallRtTgsigqueueinfo64,
		298: a.syscallPerfEventOpen,
		299: a.syscallRecvmmsg64,
		300: a.syscallFanotifyInit,
		301: a.syscallFanotifyMark,
		302: a.syscallPrlimit64,
		303: a.syscallNameToHandleAt,
		304: a.syscallOpenByHandleAt,
		305: a.syscallClockAdjtime,
		306: a.syscallSyncfs,
		307: a.syscallSendmmsg64,
		308: a.syscallSetns,
		309: a.syscallGetcpu,
		310: a.syscallProcessVmReadv64,
		311: a.syscallProcessVmWritev64,
		312: a.syscallKcmp,
		313: a.syscallFinitModule,
		314: a.syscallSchedSetattr,
		315: a.syscallSchedGetattr,
		316: a.syscallRenameat2,
		317: a.syscallSeccomp,
		318: a.syscallGetrandom,
		319: a.syscallMemfdCreate,
		320: a.syscallKexecFileLoad,
		321: a.syscallBpf,
		322: a.syscallExecveat64,
		323: a.syscallUserfaultfd,
		324: a.syscallMembarrier,
		325: a.syscallMlock2,
		326: a.syscallCopyFileRange,
		327: a.syscallPreadv264,
		328: a.syscallPwritev264,
		329: a.syscallPkeyMprotect,
		330: a.syscallPkeyAlloc,
		331: a.syscallPkeyFree,
		332: a.syscallStatx,
		333: a.syscallIoPgetevents,
		334: a.syscallRseq,
		424: a.syscallPidfdSendSignal,
		425: a.syscallIoUringSetup,
		426: a.syscallIoUringEnter,
		427: a.syscallIoUringRegister,
		428: a.syscallOpenTree,
		429: a.syscallMoveMount,
		430: a.syscallFsopen,
		431: a.syscallFsconfig,
		432: a.syscallFsmount,
		433: a.syscallFspick,
		434: a.syscallPidfdOpen,
		435: a.syscallClone3,
		436: a.syscallCloseRange,
		437: a.syscallOpenat2,
		438: a.syscallPidfdGetfd,
		439: a.syscallFaccessat2,
		440: a.syscallProcessMadvise,
		441: a.syscallEpollPwait2,
		512: a.syscallRtSigactionX32,
		513: a.syscallRtSigreturnX32,
		514: a.syscallIoctlX32,
		515: a.syscallReadvX32,
		516: a.syscallWritevX32,
		517: a.syscallRecvfromX32,
		518: a.syscallSendmsgX32,
		519: a.syscallRecvmsgX32,
		520: a.syscallExecveX32,
		521: a.syscallPtraceX32,
		522: a.syscallRtSigpendingX32,
		523: a.syscallRtSigtimedwaitX32,
		524: a.syscallRtSigqueueinfoX32,
		525: a.syscallSigaltstackX32,
		526: a.syscallTimerCreateX32,
		527: a.syscallMqNotifyX32,
		528: a.syscallKexecLoadX32,
		529: a.syscallWaitidX32,
		530: a.syscallSetRobustListX32,
		531: a.syscallGetRobustListX32,
		532: a.syscallVmspliceX32,
		533: a.syscallMovePagesX32,
		534: a.syscallPreadvX32,
		535: a.syscallPwritevX32,
		536: a.syscallRtTgsigqueueinfoX32,
		537: a.syscallRecvmmsgX32,
		538: a.syscallSendmmsgX32,
		539: a.syscallProcessVmReadvX32,
		540: a.syscallProcessVmWritevX32,
		541: a.syscallSetsockoptX32,
		542: a.syscallGetsockoptX32,
		543: a.syscallIoSetupX32,
		544: a.syscallIoSubmitX32,
		545: a.syscallExecveatX32,
		546: a.syscallPreadv2X32,
		547: a.syscallPwritev2X32,
	}
}

func (a *Art) syscallRead() error { return nil }

func (a *Art) syscallWrite() error { return nil }

func (a *Art) syscallOpen() error { return nil }

func (a *Art) syscallClose() error { return nil }

func (a *Art) syscallStat() error { return nil }

func (a *Art) syscallFstat() error { return nil }

func (a *Art) syscallLstat() error { return nil }

func (a *Art) syscallPoll() error { return nil }

func (a *Art) syscallLseek() error { return nil }

func (a *Art) syscallMmap() error { return nil }

func (a *Art) syscallMprotect() error { return nil }

func (a *Art) syscallMunmap() error { return nil }

func (a *Art) syscallBrk() error { return nil }

func (a *Art) syscallRtSigaction64() error { return nil }

func (a *Art) syscallRtSigprocmask() error { return nil }

func (a *Art) syscallRtSigreturn64() error { return nil }

func (a *Art) syscallIoctl64() error { return nil }

func (a *Art) syscallPread64() error { return nil }

func (a *Art) syscallPwrite64() error { return nil }

func (a *Art) syscallReadv64() error { return nil }

func (a *Art) syscallWritev64() error { return nil }

func (a *Art) syscallAccess() error { return nil }

func (a *Art) syscallPipe() error { return nil }

func (a *Art) syscallSelect() error { return nil }

func (a *Art) syscallSchedYield() error { return nil }

func (a *Art) syscallMremap() error { return nil }

func (a *Art) syscallMsync() error { return nil }

func (a *Art) syscallMincore() error { return nil }

func (a *Art) syscallMadvise() error { return nil }

func (a *Art) syscallShmget() error { return nil }

func (a *Art) syscallShmat() error { return nil }

func (a *Art) syscallShmctl() error { return nil }

func (a *Art) syscallDup() error { return nil }

func (a *Art) syscallDup2() error { return nil }

func (a *Art) syscallPause() error { return nil }

func (a *Art) syscallNanosleep() error { return nil }

func (a *Art) syscallGetitimer() error { return nil }

func (a *Art) syscallAlarm() error { return nil }

func (a *Art) syscallSetitimer() error { return nil }

func (a *Art) syscallGetpid() error { return nil }

func (a *Art) syscallSendfile() error { return nil }

func (a *Art) syscallSocket() error { return nil }

func (a *Art) syscallConnect() error { return nil }

func (a *Art) syscallAccept() error { return nil }

func (a *Art) syscallSendto() error { return nil }

func (a *Art) syscallRecvfrom64() error { return nil }

func (a *Art) syscallSendmsg64() error { return nil }

func (a *Art) syscallRecvmsg64() error { return nil }

func (a *Art) syscallShutdown() error { return nil }

func (a *Art) syscallBind() error { return nil }

func (a *Art) syscallListen() error { return nil }

func (a *Art) syscallGetsockname() error { return nil }

func (a *Art) syscallGetpeername() error { return nil }

func (a *Art) syscallSocketpair() error { return nil }

func (a *Art) syscallSetsockopt64() error { return nil }

func (a *Art) syscallGetsockopt64() error { return nil }

func (a *Art) syscallClone() error { return nil }

func (a *Art) syscallFork() error { return nil }

func (a *Art) syscallVfork() error { return nil }

func (a *Art) syscallExecve64() error { return nil }

func (a *Art) syscallExit() error { return nil }

func (a *Art) syscallWait4() error { return nil }

func (a *Art) syscallKill() error { return nil }

func (a *Art) syscallUname() error { return nil }

func (a *Art) syscallSemget() error { return nil }

func (a *Art) syscallSemop() error { return nil }

func (a *Art) syscallSemctl() error { return nil }

func (a *Art) syscallShmdt() error { return nil }

func (a *Art) syscallMsgget() error { return nil }

func (a *Art) syscallMsgsnd() error { return nil }

func (a *Art) syscallMsgrcv() error { return nil }

func (a *Art) syscallMsgctl() error { return nil }

func (a *Art) syscallFcntl() error { return nil }

func (a *Art) syscallFlock() error { return nil }

func (a *Art) syscallFsync() error { return nil }

func (a *Art) syscallFdatasync() error { return nil }

func (a *Art) syscallTruncate() error { return nil }

func (a *Art) syscallFtruncate() error { return nil }

func (a *Art) syscallGetdents() error { return nil }

func (a *Art) syscallGetcwd() error { return nil }

func (a *Art) syscallChdir() error { return nil }

func (a *Art) syscallFchdir() error { return nil }

func (a *Art) syscallRename() error { return nil }

func (a *Art) syscallMkdir() error { return nil }

func (a *Art) syscallRmdir() error { return nil }

func (a *Art) syscallCreat() error { return nil }

func (a *Art) syscallLink() error { return nil }

func (a *Art) syscallUnlink() error { return nil }

func (a *Art) syscallSymlink() error { return nil }

func (a *Art) syscallReadlink() error { return nil }

func (a *Art) syscallChmod() error { return nil }

func (a *Art) syscallFchmod() error { return nil }

func (a *Art) syscallChown() error { return nil }

func (a *Art) syscallFchown() error { return nil }

func (a *Art) syscallLchown() error { return nil }

func (a *Art) syscallUmask() error { return nil }

func (a *Art) syscallGettimeofday() error { return nil }

func (a *Art) syscallGetrlimit() error { return nil }

func (a *Art) syscallGetrusage() error { return nil }

func (a *Art) syscallSysinfo() error { return nil }

func (a *Art) syscallTimes() error { return nil }

func (a *Art) syscallPtrace64() error { return nil }

func (a *Art) syscallGetuid() error { return nil }

func (a *Art) syscallSyslog() error { return nil }

func (a *Art) syscallGetgid() error { return nil }

func (a *Art) syscallSetuid() error { return nil }

func (a *Art) syscallSetgid() error { return nil }

func (a *Art) syscallGeteuid() error { return nil }

func (a *Art) syscallGetegid() error { return nil }

func (a *Art) syscallSetpgid() error { return nil }

func (a *Art) syscallGetppid() error { return nil }

func (a *Art) syscallGetpgrp() error { return nil }

func (a *Art) syscallSetsid() error { return nil }

func (a *Art) syscallSetreuid() error { return nil }

func (a *Art) syscallSetregid() error { return nil }

func (a *Art) syscallGetgroups() error { return nil }

func (a *Art) syscallSetgroups() error { return nil }

func (a *Art) syscallSetresuid() error { return nil }

func (a *Art) syscallGetresuid() error { return nil }

func (a *Art) syscallSetresgid() error { return nil }

func (a *Art) syscallGetresgid() error { return nil }

func (a *Art) syscallGetpgid() error { return nil }

func (a *Art) syscallSetfsuid() error { return nil }

func (a *Art) syscallSetfsgid() error { return nil }

func (a *Art) syscallGetsid() error { return nil }

func (a *Art) syscallCapget() error { return nil }

func (a *Art) syscallCapset() error { return nil }

func (a *Art) syscallRtSigpending64() error { return nil }

func (a *Art) syscallRtSigtimedwait64() error { return nil }

func (a *Art) syscallRtSigqueueinfo64() error { return nil }

func (a *Art) syscallRtSigsuspend() error { return nil }

func (a *Art) syscallSigaltstack64() error { return nil }

func (a *Art) syscallUtime() error { return nil }

func (a *Art) syscallMknod() error { return nil }

func (a *Art) syscallUselib64() error { return nil }

func (a *Art) syscallPersonality() error { return nil }

func (a *Art) syscallUstat() error { return nil }

func (a *Art) syscallStatfs() error { return nil }

func (a *Art) syscallFstatfs() error { return nil }

func (a *Art) syscallSysfs() error { return nil }

func (a *Art) syscallGetpriority() error { return nil }

func (a *Art) syscallSetpriority() error { return nil }

func (a *Art) syscallSchedSetparam() error { return nil }

func (a *Art) syscallSchedGetparam() error { return nil }

func (a *Art) syscallSchedSetscheduler() error { return nil }

func (a *Art) syscallSchedGetscheduler() error { return nil }

func (a *Art) syscallSchedGetPriorityMax() error { return nil }

func (a *Art) syscallSchedGetPriorityMin() error { return nil }

func (a *Art) syscallSchedRrGetInterval() error { return nil }

func (a *Art) syscallMlock() error { return nil }

func (a *Art) syscallMunlock() error { return nil }

func (a *Art) syscallMlockall() error { return nil }

func (a *Art) syscallMunlockall() error { return nil }

func (a *Art) syscallVhangup() error { return nil }

func (a *Art) syscallModifyLdt() error { return nil }

func (a *Art) syscallPivotRoot() error { return nil }

func (a *Art) syscallSysctl64() error { return nil }

func (a *Art) syscallPrctl() error { return nil }

func (a *Art) syscallArchPrctl() error { return nil }

func (a *Art) syscallAdjtimex() error { return nil }

func (a *Art) syscallSetrlimit() error { return nil }

func (a *Art) syscallChroot() error { return nil }

func (a *Art) syscallSync() error { return nil }

func (a *Art) syscallAcct() error { return nil }

func (a *Art) syscallSettimeofday() error { return nil }

func (a *Art) syscallMount() error { return nil }

func (a *Art) syscallUmount2() error { return nil }

func (a *Art) syscallSwapon() error { return nil }

func (a *Art) syscallSwapoff() error { return nil }

func (a *Art) syscallReboot() error { return nil }

func (a *Art) syscallSethostname() error { return nil }

func (a *Art) syscallSetdomainname() error { return nil }

func (a *Art) syscallIopl() error { return nil }

func (a *Art) syscallIoperm() error { return nil }

func (a *Art) syscallCreateModule64() error { return nil }

func (a *Art) syscallInitModule() error { return nil }

func (a *Art) syscallDeleteModule() error { return nil }

func (a *Art) syscallGetKernelSyms64() error { return nil }

func (a *Art) syscallQueryModule64() error { return nil }

func (a *Art) syscallQuotactl() error { return nil }

func (a *Art) syscallNfsservctl64() error { return nil }

func (a *Art) syscallGetpmsg() error { return nil }

func (a *Art) syscallPutpmsg() error { return nil }

func (a *Art) syscallAfsSyscall() error { return nil }

func (a *Art) syscallTuxcall() error { return nil }

func (a *Art) syscallSecurity() error { return nil }

func (a *Art) syscallGettid() error { return nil }

func (a *Art) syscallReadahead() error { return nil }

func (a *Art) syscallSetxattr() error { return nil }

func (a *Art) syscallLsetxattr() error { return nil }

func (a *Art) syscallFsetxattr() error { return nil }

func (a *Art) syscallGetxattr() error { return nil }

func (a *Art) syscallLgetxattr() error { return nil }

func (a *Art) syscallFgetxattr() error { return nil }

func (a *Art) syscallListxattr() error { return nil }

func (a *Art) syscallLlistxattr() error { return nil }

func (a *Art) syscallFlistxattr() error { return nil }

func (a *Art) syscallRemovexattr() error { return nil }

func (a *Art) syscallLremovexattr() error { return nil }

func (a *Art) syscallFremovexattr() error { return nil }

func (a *Art) syscallTkill() error { return nil }

func (a *Art) syscallTime() error { return nil }

func (a *Art) syscallFutex() error { return nil }

func (a *Art) syscallSchedSetaffinity() error { return nil }

func (a *Art) syscallSchedGetaffinity() error { return nil }

func (a *Art) syscallSetThreadArea64() error { return nil }

func (a *Art) syscallIoSetup64() error { return nil }

func (a *Art) syscallIoDestroy() error { return nil }

func (a *Art) syscallIoGetevents() error { return nil }

func (a *Art) syscallIoSubmit64() error { return nil }

func (a *Art) syscallIoCancel() error { return nil }

func (a *Art) syscallGetThreadArea64() error { return nil }

func (a *Art) syscallLookupDcookie() error { return nil }

func (a *Art) syscallEpollCreate() error { return nil }

func (a *Art) syscallEpollCtlOld64() error { return nil }

func (a *Art) syscallEpollWaitOld64() error { return nil }

func (a *Art) syscallRemapFilePages() error { return nil }

func (a *Art) syscallGetdents64() error { return nil }

func (a *Art) syscallSetTidAddress() error { return nil }

func (a *Art) syscallRestartSyscall() error { return nil }

func (a *Art) syscallSemtimedop() error { return nil }

func (a *Art) syscallFadvise64() error { return nil }

func (a *Art) syscallTimerCreate64() error { return nil }

func (a *Art) syscallTimerSettime() error { return nil }

func (a *Art) syscallTimerGettime() error { return nil }

func (a *Art) syscallTimerGetoverrun() error { return nil }

func (a *Art) syscallTimerDelete() error { return nil }

func (a *Art) syscallClockSettime() error { return nil }

func (a *Art) syscallClockGettime() error { return nil }

func (a *Art) syscallClockGetres() error { return nil }

func (a *Art) syscallClockNanosleep() error { return nil }

func (a *Art) syscallExitGroup() error { return nil }

func (a *Art) syscallEpollWait() error { return nil }

func (a *Art) syscallEpollCtl() error { return nil }

func (a *Art) syscallTgkill() error { return nil }

func (a *Art) syscallUtimes() error { return nil }

func (a *Art) syscallVserver64() error { return nil }

func (a *Art) syscallMbind() error { return nil }

func (a *Art) syscallSetMempolicy() error { return nil }

func (a *Art) syscallGetMempolicy() error { return nil }

func (a *Art) syscallMqOpen() error { return nil }

func (a *Art) syscallMqUnlink() error { return nil }

func (a *Art) syscallMqTimedsend() error { return nil }

func (a *Art) syscallMqTimedreceive() error { return nil }

func (a *Art) syscallMqNotify64() error { return nil }

func (a *Art) syscallMqGetsetattr() error { return nil }

func (a *Art) syscallKexecLoad64() error { return nil }

func (a *Art) syscallWaitid64() error { return nil }

func (a *Art) syscallAddKey() error { return nil }

func (a *Art) syscallRequestKey() error { return nil }

func (a *Art) syscallKeyctl() error { return nil }

func (a *Art) syscallIoprioSet() error { return nil }

func (a *Art) syscallIoprioGet() error { return nil }

func (a *Art) syscallInotifyInit() error { return nil }

func (a *Art) syscallInotifyAddWatch() error { return nil }

func (a *Art) syscallInotifyRmWatch() error { return nil }

func (a *Art) syscallMigratePages() error { return nil }

func (a *Art) syscallOpenat() error { return nil }

func (a *Art) syscallMkdirat() error { return nil }

func (a *Art) syscallMknodat() error { return nil }

func (a *Art) syscallFchownat() error { return nil }

func (a *Art) syscallFutimesat() error { return nil }

func (a *Art) syscallNewfstatat() error { return nil }

func (a *Art) syscallUnlinkat() error { return nil }

func (a *Art) syscallRenameat() error { return nil }

func (a *Art) syscallLinkat() error { return nil }

func (a *Art) syscallSymlinkat() error { return nil }

func (a *Art) syscallReadlinkat() error { return nil }

func (a *Art) syscallFchmodat() error { return nil }

func (a *Art) syscallFaccessat() error { return nil }

func (a *Art) syscallPselect6() error { return nil }

func (a *Art) syscallPpoll() error { return nil }

func (a *Art) syscallUnshare() error { return nil }

func (a *Art) syscallSetRobustList64() error { return nil }

func (a *Art) syscallGetRobustList64() error { return nil }

func (a *Art) syscallSplice() error { return nil }

func (a *Art) syscallTee() error { return nil }

func (a *Art) syscallSyncFileRange() error { return nil }

func (a *Art) syscallVmsplice64() error { return nil }

func (a *Art) syscallMovePages64() error { return nil }

func (a *Art) syscallUtimensat() error { return nil }

func (a *Art) syscallEpollPwait() error { return nil }

func (a *Art) syscallSignalfd() error { return nil }

func (a *Art) syscallTimerfdCreate() error { return nil }

func (a *Art) syscallEventfd() error { return nil }

func (a *Art) syscallFallocate() error { return nil }

func (a *Art) syscallTimerfdSettime() error { return nil }

func (a *Art) syscallTimerfdGettime() error { return nil }

func (a *Art) syscallAccept4() error { return nil }

func (a *Art) syscallSignalfd4() error { return nil }

func (a *Art) syscallEventfd2() error { return nil }

func (a *Art) syscallEpollCreate1() error { return nil }

func (a *Art) syscallDup3() error { return nil }

func (a *Art) syscallPipe2() error { return nil }

func (a *Art) syscallInotifyInit1() error { return nil }

func (a *Art) syscallPreadv64() error { return nil }

func (a *Art) syscallPwritev64() error { return nil }

func (a *Art) syscallRtTgsigqueueinfo64() error { return nil }

func (a *Art) syscallPerfEventOpen() error { return nil }

func (a *Art) syscallRecvmmsg64() error { return nil }

func (a *Art) syscallFanotifyInit() error { return nil }

func (a *Art) syscallFanotifyMark() error { return nil }

func (a *Art) syscallPrlimit64() error { return nil }

func (a *Art) syscallNameToHandleAt() error { return nil }

func (a *Art) syscallOpenByHandleAt() error { return nil }

func (a *Art) syscallClockAdjtime() error { return nil }

func (a *Art) syscallSyncfs() error { return nil }

func (a *Art) syscallSendmmsg64() error { return nil }

func (a *Art) syscallSetns() error { return nil }

func (a *Art) syscallGetcpu() error { return nil }

func (a *Art) syscallProcessVmReadv64() error { return nil }

func (a *Art) syscallProcessVmWritev64() error { return nil }

func (a *Art) syscallKcmp() error { return nil }

func (a *Art) syscallFinitModule() error { return nil }

func (a *Art) syscallSchedSetattr() error { return nil }

func (a *Art) syscallSchedGetattr() error { return nil }

func (a *Art) syscallRenameat2() error { return nil }

func (a *Art) syscallSeccomp() error { return nil }

func (a *Art) syscallGetrandom() error { return nil }

func (a *Art) syscallMemfdCreate() error { return nil }

func (a *Art) syscallKexecFileLoad() error { return nil }

func (a *Art) syscallBpf() error { return nil }

func (a *Art) syscallExecveat64() error { return nil }

func (a *Art) syscallUserfaultfd() error { return nil }

func (a *Art) syscallMembarrier() error { return nil }

func (a *Art) syscallMlock2() error { return nil }

func (a *Art) syscallCopyFileRange() error { return nil }

func (a *Art) syscallPreadv264() error { return nil }

func (a *Art) syscallPwritev264() error { return nil }

func (a *Art) syscallPkeyMprotect() error { return nil }

func (a *Art) syscallPkeyAlloc() error { return nil }

func (a *Art) syscallPkeyFree() error { return nil }

func (a *Art) syscallStatx() error { return nil }

func (a *Art) syscallIoPgetevents() error { return nil }

func (a *Art) syscallRseq() error { return nil }

func (a *Art) syscallPidfdSendSignal() error { return nil }

func (a *Art) syscallIoUringSetup() error { return nil }

func (a *Art) syscallIoUringEnter() error { return nil }

func (a *Art) syscallIoUringRegister() error { return nil }

func (a *Art) syscallOpenTree() error { return nil }

func (a *Art) syscallMoveMount() error { return nil }

func (a *Art) syscallFsopen() error { return nil }

func (a *Art) syscallFsconfig() error { return nil }

func (a *Art) syscallFsmount() error { return nil }

func (a *Art) syscallFspick() error { return nil }

func (a *Art) syscallPidfdOpen() error { return nil }

func (a *Art) syscallClone3() error { return nil }

func (a *Art) syscallCloseRange() error { return nil }

func (a *Art) syscallOpenat2() error { return nil }

func (a *Art) syscallPidfdGetfd() error { return nil }

func (a *Art) syscallFaccessat2() error { return nil }

func (a *Art) syscallProcessMadvise() error { return nil }

func (a *Art) syscallEpollPwait2() error { return nil }

func (a *Art) syscallRtSigactionX32() error { return nil }

func (a *Art) syscallRtSigreturnX32() error { return nil }

func (a *Art) syscallIoctlX32() error { return nil }

func (a *Art) syscallReadvX32() error { return nil }

func (a *Art) syscallWritevX32() error { return nil }

func (a *Art) syscallRecvfromX32() error { return nil }

func (a *Art) syscallSendmsgX32() error { return nil }

func (a *Art) syscallRecvmsgX32() error { return nil }

func (a *Art) syscallExecveX32() error { return nil }

func (a *Art) syscallPtraceX32() error { return nil }

func (a *Art) syscallRtSigpendingX32() error { return nil }

func (a *Art) syscallRtSigtimedwaitX32() error { return nil }

func (a *Art) syscallRtSigqueueinfoX32() error { return nil }

func (a *Art) syscallSigaltstackX32() error { return nil }

func (a *Art) syscallTimerCreateX32() error { return nil }

func (a *Art) syscallMqNotifyX32() error { return nil }

func (a *Art) syscallKexecLoadX32() error { return nil }

func (a *Art) syscallWaitidX32() error { return nil }

func (a *Art) syscallSetRobustListX32() error { return nil }

func (a *Art) syscallGetRobustListX32() error { return nil }

func (a *Art) syscallVmspliceX32() error { return nil }

func (a *Art) syscallMovePagesX32() error { return nil }

func (a *Art) syscallPreadvX32() error { return nil }

func (a *Art) syscallPwritevX32() error { return nil }

func (a *Art) syscallRtTgsigqueueinfoX32() error { return nil }

func (a *Art) syscallRecvmmsgX32() error { return nil }

func (a *Art) syscallSendmmsgX32() error { return nil }

func (a *Art) syscallProcessVmReadvX32() error { return nil }

func (a *Art) syscallProcessVmWritevX32() error { return nil }

func (a *Art) syscallSetsockoptX32() error { return nil }

func (a *Art) syscallGetsockoptX32() error { return nil }

func (a *Art) syscallIoSetupX32() error { return nil }

func (a *Art) syscallIoSubmitX32() error { return nil }

func (a *Art) syscallExecveatX32() error { return nil }

func (a *Art) syscallPreadv2X32() error { return nil }

func (a *Art) syscallPwritev2X32() error { return nil }
