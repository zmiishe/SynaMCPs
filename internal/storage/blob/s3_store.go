package blob

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/zmiishe/synamcps/internal/config"
)

type Store struct {
	mu     sync.RWMutex
	blobs  map[string][]byte
	s3     *minio.Client
	bucket string
}

func NewStore(cfg config.Config) (*Store, error) {
	s := &Store{
		blobs:  map[string][]byte{},
		bucket: cfg.S3.Bucket,
	}
	if cfg.S3.Endpoint == "" {
		return s, nil
	}
	endpoint := strings.TrimPrefix(strings.TrimPrefix(cfg.S3.Endpoint, "http://"), "https://")
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey(), cfg.SecretKey(), ""),
		Secure: cfg.S3.UseSSL || strings.HasPrefix(cfg.S3.Endpoint, "https://"),
	})
	if err != nil {
		return nil, err
	}
	s.s3 = client
	if err := s.ensureBucket(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Put(_ context.Context, key string, payload []byte) error {
	if s.s3 != nil {
		_, err := s.s3.PutObject(context.Background(), s.bucket, key, bytes.NewReader(payload), int64(len(payload)), minio.PutObjectOptions{})
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[key] = payload
	return nil
}

func (s *Store) Get(_ context.Context, key string) ([]byte, bool, error) {
	if s.s3 != nil {
		obj, err := s.s3.GetObject(context.Background(), s.bucket, key, minio.GetObjectOptions{})
		if err != nil {
			return nil, false, err
		}
		defer obj.Close()
		data, err := io.ReadAll(obj)
		if err != nil {
			return nil, false, err
		}
		return data, true, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.blobs[key]
	return v, ok, nil
}

func (s *Store) ensureBucket(ctx context.Context) error {
	if s.s3 == nil {
		return nil
	}
	if s.bucket == "" {
		return errors.New("s3 bucket is empty")
	}
	exists, err := s.s3.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.s3.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{})
}

func (s *Store) Ping(ctx context.Context) error {
	if s.s3 == nil {
		return nil
	}
	_, err := s.s3.BucketExists(ctx, s.bucket)
	return err
}
