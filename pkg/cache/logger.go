package cache

type Logger interface {
	Debugf(string, ...interface{})
	Errorf(string, ...interface{})
}
