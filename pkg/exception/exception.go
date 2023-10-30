package exception

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type PortageException struct {
	value interface{}
}

func (e *PortageException) Error() string {
	if s, ok := e.value.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", e.value)
}

func NewPortageException(value interface{}) *PortageException {
	return &PortageException{value}
}

type PortageKeyError struct {
	// *KeyError
	*PortageException
}

func NewPortageKeyError(value interface{}) *PortageKeyError {
	return &PortageKeyError{
		// NewKeyError(value),
		NewPortageException(value)}
}

type CorruptionError struct {
	*PortageException
}

func NewCorruptionError(value interface{}) *CorruptionError {
	return &CorruptionError{NewPortageException(value)}
}

type InvalidDependString struct {
	*PortageException
	Errors []error
}

func NewInvalidDependString(value interface{}, errors []error) *InvalidDependString {
	return &InvalidDependString{NewPortageException(value), errors}
}

type InvalidVersionString struct {
	*PortageException
}

func NewInvalidVersionString(value interface{}) *InvalidVersionString {
	return &InvalidVersionString{NewPortageException(value)}
}

type SecurityViolation struct {
	*PortageException
}

func NewSecurityViolation(value interface{}) *SecurityViolation {
	return &SecurityViolation{NewPortageException(value)}
}

type IncorrectParameter struct {
	*PortageException
}

func NewIncorrectParameter(value interface{}) *IncorrectParameter {
	return &IncorrectParameter{NewPortageException(value)}
}

type MissingParameter struct {
	*PortageException
}

func NewMissingParameter(value interface{}) *MissingParameter {
	return &MissingParameter{NewPortageException(value)}
}

type ParseError struct {
	*PortageException
}

func NewParseError(value interface{}) *ParseError {
	return &ParseError{NewPortageException(value)}
}

type InvalidData struct {
	*PortageException
	Category string
}

func NewInvalidData(value interface{}, category string) *InvalidData {
	return &InvalidData{NewPortageException(value), category}
}

type InvalidDataType struct {
	*PortageException
}

func NewInvalidDataType(value interface{}) *InvalidDataType {
	return &InvalidDataType{NewPortageException(value)}
}

type InvalidLocation struct {
	*PortageException
}

func NewInvalidLocation(value interface{}) *InvalidLocation {
	return &InvalidLocation{NewPortageException(value)}
}

type FileNotFound struct {
	*InvalidLocation
}

func NewFileNotFound(value interface{}) *FileNotFound {
	return &FileNotFound{NewInvalidLocation(value)}
}

type DirectoryNotFound struct {
	*InvalidLocation
}

func NewDirectoryNotFound(value interface{}) *DirectoryNotFound {
	return &DirectoryNotFound{NewInvalidLocation(value)}
}

type IsADirectory struct {
	*PortageException
}

func NewIsADirectory(value interface{}) *IsADirectory {
	return &IsADirectory{NewPortageException(value)}
}

type OperationNotPermitted struct {
	*PortageException
}

func NewOperationNotPermitted(value interface{}) *OperationNotPermitted {
	return &OperationNotPermitted{NewPortageException(value)}
}

type OperationNotSupported struct {
	*PortageException
}

func NewOperationNotSupported(value interface{}) *OperationNotSupported {
	return &OperationNotSupported{NewPortageException(value)}
}

type PermissionDenied struct {
	*PortageException
}

func NewPermissionDenied(value interface{}) *PermissionDenied {
	return &PermissionDenied{NewPortageException(value)}
}

type TryAgain struct {
	*PortageException
}

func NewTryAgain(value interface{}) *TryAgain {
	return &TryAgain{NewPortageException(value)}
}

type TimeoutException struct {
	*PortageException
}

func NewTimeoutException(value interface{}) *TimeoutException {
	return &TimeoutException{NewPortageException(value)}
}

type AlarmSignal struct {
	*TimeoutException
	signum int
	frame  []uintptr
	ch     chan os.Signal
}

func NewAlarmSignal(value interface{}, signum int, frame []uintptr) *AlarmSignal {
	return &AlarmSignal{NewTimeoutException(value), signum, frame, make(chan os.Signal, 1)}
}

func (e *AlarmSignal) Unregister() {
	signal.Stop(e.ch)
}

func (e *AlarmSignal) Register(timeSec int) {
	e.ch = make(chan os.Signal, 1)
	signal.Notify(e.ch, syscall.SIGALRM)
	go func() {
		for {
			<-e.ch
			panic(NewAlarmSignal("alarm signal", e.signum, e.frame))
		}
	}()
	time.AfterFunc(time.Duration(timeSec)*time.Second, func() {
		e.ch <- syscall.SIGALRM
	})
}

func (e *AlarmSignal) signalHandler(signum int, frame []uintptr) {
	signal.Stop(e.ch)
	panic(NewAlarmSignal("alarm signal", signum, frame))
}

type ReadOnlyFileSystem struct {
	*PortageException
}

func NewReadOnlyFileSystem(value interface{}) *ReadOnlyFileSystem {
	return &ReadOnlyFileSystem{NewPortageException(value)}
}

type CommandNotFound struct {
	*PortageException
}

func NewCommandNotFound(value interface{}) *CommandNotFound {
	return &CommandNotFound{NewPortageException(value)}
}

type AmbiguousPackageName struct {
	*PortageException
}

func NewAmbiguousPackageName(value interface{}) *AmbiguousPackageName {
	return &AmbiguousPackageName{NewPortageException(value)}
}

type PortagePackageException struct {
	*PortageException
}

func NewPortagePackageException(value interface{}) *PortagePackageException {
	return &PortagePackageException{NewPortageException(value)}
}

type PackageNotFound struct {
	*PortagePackageException
}

func NewPackageNotFound(value interface{}) *PackageNotFound {
	return &PackageNotFound{NewPortagePackageException(value)}
}

type PackageSetNotFound struct {
	*PortagePackageException
}

func NewPackageSetNotFound(value interface{}) *PackageSetNotFound {
	return &PackageSetNotFound{NewPortagePackageException(value)}
}

type InvalidPackageName struct {
	*PortagePackageException
}

func NewInvalidPackageName(value interface{}) *InvalidPackageName {
	return &InvalidPackageName{NewPortagePackageException(value)}
}

type InvalidBinaryPackageFormat struct {
	*PortagePackageException
}

func NewInvalidBinaryPackageFormat(value interface{}) *InvalidBinaryPackageFormat {
	return &InvalidBinaryPackageFormat{NewPortagePackageException(value)}
}

type InvalidCompressionMethod struct {
	*PortagePackageException
}

func NewInvalidCompressionMethod(value interface{}) *InvalidCompressionMethod {
	return &InvalidCompressionMethod{NewPortagePackageException(value)}
}

type CompressorNotFound struct {
	*PortagePackageException
}

func NewCompressorNotFound(value interface{}) *CompressorNotFound {
	return &CompressorNotFound{NewPortagePackageException(value)}
}

type CompressorOperationFailed struct {
	*PortagePackageException
}

func NewCompressorOperationFailed(value interface{}) *CompressorOperationFailed {
	return &CompressorOperationFailed{NewPortagePackageException(value)}
}

type InvalidAtom struct {
	*PortagePackageException
	category string
}

func NewInvalidAtom(value interface{}, category string) *InvalidAtom {
	return &InvalidAtom{NewPortagePackageException(value), category}
}

type UnsupportedAPIException struct {
	*PortagePackageException
	cpv  string
	eapi string
}

func NewUnsupportedAPIException(cpv string, eapi string) *UnsupportedAPIException {
	return &UnsupportedAPIException{NewPortagePackageException(""), cpv, eapi}
}

func (e *UnsupportedAPIException) Error() string {
	return e.String()
}

func (e *UnsupportedAPIException) String() string {
	msg := fmt.Sprintf("Unable to do any operations on '%s', since its EAPI is higher than this portage version's. Please upgrade to a portage version that supports EAPI '%s'.", e.cpv, e.eapi)
	return msg
}

type SignatureException struct {
	*PortageException
}

func NewSignatureException(value interface{}) *SignatureException {
	return &SignatureException{NewPortageException(value)}
}

type DigestException struct {
	*SignatureException
}

func NewDigestException(value interface{}) *DigestException {
	return &DigestException{NewSignatureException(value)}
}

type GPGException struct {
	*SignatureException
}

func NewGPGException(value interface{}) *GPGException {
	return &GPGException{NewSignatureException(value)}
}

type MissingSignature struct {
	*SignatureException
}

func NewMissingSignature(value interface{}) *MissingSignature {
	return &MissingSignature{NewSignatureException(value)}
}

type InvalidSignature struct {
	*SignatureException
}

func NewInvalidSignature(value interface{}) *InvalidSignature {
	return &InvalidSignature{NewSignatureException(value)}
}

type UntrustedSignature struct {
	*SignatureException
}

func NewUntrustedSignature(value interface{}) *UntrustedSignature {
	return &UntrustedSignature{NewSignatureException(value)}
}

type NotImplementedError struct{}

func (e NotImplementedError) Error() string {
	return "Not implemented"
}
