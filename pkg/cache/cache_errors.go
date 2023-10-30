package cache

import "fmt"

type CacheError struct {
	error string
}

func (e *CacheError) Error() string {
	return fmt.Sprintf("cache error: %s", e.error)
}

type InitializationError struct {
	*CacheError
	class_name string
	error      error
}

func NewInitializationError(class_name string, err error) *InitializationError {
	return &InitializationError{
		CacheError: &CacheError{error: fmt.Sprintf("creation of instance %s failed due to %s", class_name, err)},
		class_name: class_name,
		error:      err,
	}
}

func (e *InitializationError) Error() string {
	return fmt.Sprintf("creation of instance %s failed due to %s", e.class_name, e.error)
}

type CacheCorruption struct {
	*CacheError
	key string
	ex  error
}

func NewCacheCorruption(key string, ex error) *CacheCorruption {
	return &CacheCorruption{
		CacheError: &CacheError{error: fmt.Sprintf("creation of instance %s failed due to %s", class_name, err)},
		key:        key,
		ex:         ex,
	}
}

func (e *CacheCorruption) Error() string {
	return fmt.Sprintf("%s is corrupt: %s", e.key, e.ex)
}

type GeneralCacheCorruption struct {
	*CacheError
	ex error
}

func NewGeneralCacheCorruption(ex error) *GeneralCacheCorruption {
	return &GeneralCacheCorruption{
		ex: ex,
	}
}

func (e *GeneralCacheCorruption) Error() string {
	return fmt.Sprintf("corruption detected: %s", e.ex)
}

type InvalidRestriction struct {
	key         string
	restriction string
	ex          error
}

func NewInvalidRestriction(key string, restriction string, ex error) *InvalidRestriction {
	return &InvalidRestriction{
		key:         key,
		restriction: restriction,
		ex:          ex,
	}
}

func (e *InvalidRestriction) Error() string {
	return fmt.Sprintf("%s:%s is not valid: %s", e.key, e.restriction, e.ex)
}

type ReadOnlyRestriction struct {
	*CacheError
	info string
}

func NewReadOnlyRestriction(info string) *ReadOnlyRestriction {
	return &ReadOnlyRestriction{
		info: info,
	}
}

func (e *ReadOnlyRestriction) Error() string {
	return fmt.Sprintf("cache is non-modifiable%s", e.info)
}

type StatCollision struct {
	*CacheError
	key      string
	filename string
	mtime    int64
	size     int64
}

func NewStatCollision(key string, filename string, mtime int64, size int64) *StatCollision {
	return &StatCollision{
		key:      key,
		filename: filename,
		mtime:    mtime,
		size:     size,
	}
}

func (e *StatCollision) Error() string {
	return fmt.Sprintf("%s has stat collision with size %d and mtime %d", e.key, e.size, e.mtime)
}
