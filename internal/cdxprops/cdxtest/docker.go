package cdxtest

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Container is a lean wrapper on top of testcontainers-go/docker allowing build and
// run of the container based on a provided Dockerfile. The container is built from
// the specified Dockerfile and started automatically. When Cleanup() is called, both
// the container and its built image are removed from the system.
//
// Example usage:
//
//	container, err := NewContainer(ctx, "path/to/Dockerfile")
//	if err != nil {
//	    return err
//	}
//	defer container.Cleanup(ctx)
type Container struct {
	container testcontainers.Container
	info      *container.InspectResponse
}

func NewContainer(ctx context.Context, path string) (Container, error) {
	path, name := filepath.Split(path)

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    path,
			Dockerfile: name,
		},
		WaitingFor: wait.ForExit(),
	}

	c, err := testcontainers.GenericContainer(ctx,
		testcontainers.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
	if err != nil {
		return Container{}, fmt.Errorf("starting generic container: %w", err)
	}

	info, err := c.Inspect(ctx)
	if err != nil {
		// Cleanup container if inspection fails
		_ = c.Terminate(ctx)
		return Container{}, fmt.Errorf("inspecting container: %w", err)
	}
	return Container{
		container: c,
		info:      info,
	}, nil
}

// ID returns running container ID
func (c Container) ID() string {
	return c.info.ID
}

// ImageID returns underlying image ID
func (c Container) ImageID() string {
	return c.info.Image
}

func (c Container) Cleanup(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var pErr error
			switch x := r.(type) {
			case string:
				pErr = fmt.Errorf("panic: %s", x)
			case error:
				pErr = fmt.Errorf("panic: %w", x)
			default:
				pErr = fmt.Errorf("panic: %v", x)
			}
			err = errors.Join(err, pErr)
		}
	}()
	if err := c.container.Terminate(ctx); err != nil {
		return fmt.Errorf("terminating container: %w", err)
	}

	socket := testcontainers.MustExtractDockerSocket(ctx)
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix://"+socket),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return fmt.Errorf("creating docker client from socket %s: %w", socket, err)
	}
	defer func() {
		err = cli.Close()
		if err != nil {
			slog.WarnContext(ctx, "can't close testcontainers docker client", "error", err)
		}
	}()

	_, err = cli.ImageRemove(ctx, c.info.ID, image.RemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	if err != nil {
		return fmt.Errorf("removing image %s(%s): %w", c.info.Name, c.info.ID, err)
	}

	return nil
}
