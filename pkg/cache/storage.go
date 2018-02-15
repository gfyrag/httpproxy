package cache

import (
	"time"
	"net/http"
	"errors"
	"encoding/base64"
	"path/filepath"
	"net/textproto"
	"encoding/json"
	"sort"
	"os"
	"bufio"
	"github.com/blang/vfs"
	"github.com/blang/vfs/memfs"
	"github.com/davecgh/go-spew/spew"
)

var (
	ErrRecipeNotFound = errors.New("recipe not found")
)

type Recipe struct {
	RequestDate  time.Time `json:"requestDate"`
	Request      *http.Request `json:"-"`
	ResponseDate time.Time `json:"responseDate"`
	Response     *http.Response `json:"-"`
}

func (r *Recipe) secondaryKey() string {
	res := make([]string, 0)
	for _, h := range r.Response.Header[textproto.CanonicalMIMEHeaderKey("Vary")] {
		res = append(res, r.Request.Header.Get(h))
	}
	sort.Strings(res)
	data, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func (c *Recipe) Close() {
	c.Request.Body.Close()
	c.Response.Body.Close()
}

type Storage interface {
	List(string) ([]*Recipe, error)
	Update(string, *Recipe) error
	Insert(string, *Recipe) error
	Delete(string, *Recipe) error
}

type vfsStorage struct {
	vfs.Filesystem
	basePath string
}

func (d *vfsStorage) path(key string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	path := d.basePath
	for i := 0; i < len(encoded); i += 4 {
		path = filepath.Join(path, encoded[i:i + 4])
	}
	return path
}
func (s *vfsStorage) reconstruct(p string) (*Recipe, error) {
	infoFile, err := vfs.Open(s.Filesystem, filepath.Join(p, "info.json"))
	if err != nil {
		return nil, err
	}
	defer infoFile.Close()

	recipe := &Recipe{}
	err = json.NewDecoder(infoFile).Decode(recipe)
	if err != nil {
		return nil, err
	}

	requestFile, err := vfs.Open(s.Filesystem, filepath.Join(p, "request"))
	if err != nil {
		return nil, err
	}
	defer requestFile.Close()
	recipe.Request, err = http.ReadRequest(bufio.NewReader(requestFile))
	if err != nil {
		return nil, err
	}

	responseFile, err := vfs.Open(s.Filesystem, filepath.Join(p, "response"))
	if err != nil {
		return nil, err
	}
	defer responseFile.Close()
	recipe.Response, err = http.ReadResponse(bufio.NewReader(responseFile), recipe.Request)
	if err != nil {
		return nil, err
	}
	return recipe, nil
}
func (s *vfsStorage) List(key string) ([]*Recipe, error) {
	path := s.path(key)
	fos, err := s.Filesystem.ReadDir(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make([]*Recipe, 0), nil
		}
		return nil, err
	}
	res := make([]*Recipe, 0)
	for _, fo := range fos {
		recipe, err := s.reconstruct(filepath.Join(path, fo.Name()))
		if err != nil {
			return nil, err
		}
		res = append(res, recipe)
	}
	return res, nil
}
func (s *vfsStorage) Update(key string, r *Recipe) error {
	path := filepath.Join(s.path(key), r.secondaryKey())
	infoFile, err := s.Filesystem.OpenFile(filepath.Join(path, "info.json"), os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer infoFile.Close()
	err = json.NewEncoder(infoFile).Encode(r)
	if err != nil {
		return err
	}

	requestFile, err := s.Filesystem.OpenFile(filepath.Join(path, "request"), os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer requestFile.Close()
	err = r.Request.Write(requestFile)
	if err != nil {
		return err
	}

	responseFile, err := s.Filesystem.OpenFile(filepath.Join(path, "response"), os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer responseFile.Close()
	err = r.Response.Write(responseFile)
	if err != nil {
		return err
	}

	return nil
}
func (s *vfsStorage) Insert(key string, r *Recipe) error {

	path := filepath.Join(s.path(key), r.secondaryKey())

	err := vfs.MkdirAll(s.Filesystem, path, 0777)
	if err != nil {
		return err
	}

	infoFile, err := s.Filesystem.OpenFile(filepath.Join(path, "info.json"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	defer infoFile.Close()
	err = json.NewEncoder(infoFile).Encode(r)
	if err != nil {
		return err
	}

	requestFile, err := s.Filesystem.OpenFile(filepath.Join(path, "request"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	defer requestFile.Close()
	err = r.Request.Write(requestFile)
	if err != nil {
		return err
	}

	responseFile, err := s.Filesystem.OpenFile(filepath.Join(path, "response"), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	defer responseFile.Close()
	err = r.Response.Write(responseFile)
	if err != nil {
		spew.Dump(err)
		return err
	}

	return nil
}
func (s *vfsStorage) Delete(key string, r *Recipe) error {
	return vfs.RemoveAll(s.Filesystem, filepath.Join(s.path(key), r.secondaryKey()))
}

func MemStorage() *vfsStorage {
	return &vfsStorage{Filesystem: memfs.Create(), basePath: ""}
}

func Dir(dir string) *vfsStorage {
	return &vfsStorage{Filesystem: vfs.OS(), basePath: dir}
}


