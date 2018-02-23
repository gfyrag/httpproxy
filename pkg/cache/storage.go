package cache

import (
	"time"
	"net/http"
	"encoding/base64"
	"path/filepath"
	"net/textproto"
	"encoding/json"
	"os"
	"bufio"
	"github.com/blang/vfs"
	"github.com/blang/vfs/memfs"
)

type Recipe struct {
	RequestDate  time.Time `json:"requestDate"`
	Request      *http.Request `json:"-"`
	ResponseDate time.Time `json:"responseDate"`
	Response     *http.Response `json:"-"`
}

// See RFC7234 section 4.1
func (r *Recipe) secondaryKey() string {
	res := make(map[string]string, 0)
	for _, h := range r.Response.Header[textproto.CanonicalMIMEHeaderKey("Vary")] {
		res[h] = r.Request.Header.Get(h)
	}
	data, err := json.Marshal(res)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// TODO: We should normalize
func (r *Recipe) MatchRequest(req *http.Request) bool {
	for _, h := range r.Response.Header[textproto.CanonicalMIMEHeaderKey("Vary")] {
		if req.Header.Get(h) != r.Request.Header.Get(h) {
			return false
		}
	}
	return true
}

func (c *Recipe) Close() {
	c.Request.Body.Close()
	c.Response.Body.Close()
}

type Storage struct {
	vfs.Filesystem
	basePath string
}

func (d *Storage) path(key string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(key))
	path := d.basePath
	for i := 0; i < len(encoded); i += 4 {
		path = filepath.Join(path, encoded[i:i + 4])
	}
	return path
}

// Don't close request/response files since these will be consumed by the caller.
// Therefore, it is the caller responsability to properly close file descriptors
func (s *Storage) reconstruct(p string) (*Recipe, error) {
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
	recipe.Request, err = http.ReadRequest(bufio.NewReader(requestFile))
	if err != nil {
		return nil, err
	}

	responseFile, err := vfs.Open(s.Filesystem, filepath.Join(p, "response"))
	if err != nil {
		return nil, err
	}
	recipe.Response, err = http.ReadResponse(bufio.NewReader(responseFile), recipe.Request)
	if err != nil {
		return nil, err
	}
	return recipe, nil
}
func (s *Storage) List(key string) ([]*Recipe, error) {
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

func (s *Storage) Insert(key string, r *Recipe) error {

	path := filepath.Join(s.path(key), r.secondaryKey())

	err := vfs.MkdirAll(s.Filesystem, path, 0777)
	if err != nil {
		return err
	}

	infoFile, err := s.Filesystem.OpenFile(filepath.Join(path, "info.json"), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer infoFile.Close()
	err = json.NewEncoder(infoFile).Encode(r)
	if err != nil {
		return err
	}

	requestFile, err := s.Filesystem.OpenFile(filepath.Join(path, "request"), os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer requestFile.Close()
	err = r.Request.WriteProxy(requestFile)
	if err != nil {
		return err
	}

	responseFile, err := s.Filesystem.OpenFile(filepath.Join(path, "response"), os.O_RDWR|os.O_CREATE, 0666)
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
func (s *Storage) Delete(key string, r *Recipe) error {
	return vfs.RemoveAll(s.Filesystem, filepath.Join(s.path(key), r.secondaryKey()))
}
func (s *Storage) Retrieve(r *http.Request) (*Recipe, error) {
	entries, err := s.List(PrimaryKey(r))
	if err != nil {
		return nil, err
	}
	for i, entry := range entries {
		if entry.MatchRequest(r) {
			if i < len(entries)-1 {
				for _, remainingEntry := range entries[i+1:] {
					remainingEntry.Close()
				}
			}
			return entry, nil
		}
		entry.Close()
	}
	return nil, nil
}

func MemStorage() *Storage {
	return &Storage{Filesystem: memfs.Create(), basePath: ""}
}

func Dir(dir string) *Storage {
	return &Storage{Filesystem: vfs.OS(), basePath: dir}
}


