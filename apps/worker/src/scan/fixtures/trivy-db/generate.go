//go:build ignore

// Genera trivy.db: una BD BoltDB pequeña con la forma de la de Trivy (bucket `vulnerability` con
// el JSON de cada CVE) para los tests de trivy-db.ts. No corre en CI; para regenerarla:
//
//	cd "$(mktemp -d)" && go mod init gen && go get go.etcd.io/bbolt@v1.4.0 &&
//	  go run <repo>/apps/worker/src/scan/fixtures/trivy-db/generate.go <repo>/apps/worker/src/scan/fixtures/trivy-db/trivy.db
package main

import (
	"fmt"
	"os"
	"strings"

	bolt "go.etcd.io/bbolt"
)

func main() {
	out := os.Args[1]
	_ = os.Remove(out)
	db, err := bolt.Open(out, 0o644, &bolt.Options{PageSize: 4096})
	if err != nil {
		panic(err)
	}
	defer db.Close()
	err = db.Update(func(tx *bolt.Tx) error {
		// Buckets de distribuciones antes y después, como en la BD real.
		for _, name := range []string{"Alpine 3.20", "debian 12", "ubuntu 24.04"} {
			b, err := tx.CreateBucket([]byte(name))
			if err != nil {
				return err
			}
			if err := b.Put([]byte("zlib"), []byte(`{}`)); err != nil {
				return err
			}
		}
		v, err := tx.CreateBucket([]byte("vulnerability"))
		if err != nil {
			return err
		}
		// Suficientes para que el bucket tenga páginas rama.
		for i := 0; i < 400; i++ {
			id := fmt.Sprintf("CVE-2024-%05d", i)
			if err := v.Put([]byte(id), []byte(fmt.Sprintf(`{"Title":"Vulnerabilidad %d","Severity":"LOW"}`, i))); err != nil {
				return err
			}
		}
		if err := v.Put([]byte("CVE-2023-45853"), []byte(`{"Title":"zlib: integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_6","Description":"MiniZip in zlib through 1.3 has an integer overflow.","Severity":"CRITICAL","CweIDs":["CWE-190"],"VendorSeverity":{"nvd":4,"ubuntu":2},"CVSS":{"nvd":{"V3Vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","V3Score":9.8},"redhat":{"V3Vector":"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L","V3Score":5.3}},"References":["https://nvd.nist.gov/vuln/detail/CVE-2023-45853","https://github.com/madler/zlib/pull/843"],"PublishedDate":"2023-10-14T02:15:09.323Z","LastModifiedDate":"2026-07-14T13:17:02.983Z"}`)); err != nil {
			return err
		}
		// Un valor mayor que una página: va en páginas de overflow.
		long := strings.Repeat("Descripción muy larga. ", 1000)
		if err := v.Put([]byte("CVE-2025-99999"), []byte(`{"Title":"Grande","Description":"`+long+`","Severity":"HIGH"}`)); err != nil {
			return err
		}
		// Bucket pequeño: va inline en el valor de su padre.
		small, err := tx.CreateBucket([]byte("small"))
		if err != nil {
			return err
		}
		return small.Put([]byte("k"), []byte("v"))
	})
	if err != nil {
		panic(err)
	}
}
