package cdxtest_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CZERTAINLY/Seeker/internal/cdxprops/cdxtest"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
)

func TestContainerLifecycle(t *testing.T) {
	ctx := t.Context()
	tmpDir := t.TempDir()

	// connect to docker the same way testcontainers do
	socket := testcontainers.MustExtractDockerSocket(ctx)
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socket),
		client.WithAPIVersionNegotiation(),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := cli.Close()
		require.NoError(t, err)
	})
	t.Logf("docker socket=%s", socket)

	// Create minimal Dockerfile
	dockerfile := filepath.Join(tmpDir, "Dockerfile")
	err = os.WriteFile(dockerfile, []byte("FROM busybox:latest\nCMD [\"echo\", \"hello\"]"), 0644)
	require.NoError(t, err)

	// Create and start container
	container, err := cdxtest.NewContainer(ctx, dockerfile)
	require.NoError(t, err)

	// Verify container and image is here
	containerID := container.ID()
	imageID := container.ImageID()
	t.Logf("imageID: %s, containerID: %s", imageID, containerID)

	_, err = cli.ContainerInspect(ctx, containerID)
	require.NoError(t, err)

	_, err = cli.ImageInspect(ctx, imageID)
	require.NoError(t, err)

	// Clean up
	err = container.Cleanup(ctx)
	require.NoError(t, err)

	// Verify container and image are gone
	_, err = cli.ContainerInspect(ctx, containerID)
	require.Error(t, err)
	msg := strings.ToLower(err.Error())
	require.Contains(t, msg, "no such container")

	_, err = cli.ImageInspect(ctx, imageID)
	require.Error(t, err)
	msg = strings.ToLower(err.Error())
	require.Contains(t, msg, "no such image")
}
