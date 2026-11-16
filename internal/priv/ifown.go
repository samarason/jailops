package priv

import (
	"context"

	"jailops.net/jailops/internal/sys/ifconfig"
	"jailops.net/jailops/sdk/api"
)

// Interface ownership (docs/security-model.md, "Interfaces"). The helper changes an interface only when the kernel,
// read by the helper itself at the time of the operation, shows a bridge or an epair whose description carries the
// JailOps marker. It never decides by the name, and never by what a request says. The marker is written by the helper
// only on an interface it has just created, before that interface has its name, and kept by every later description
// (a description that would remove it is refused, clearing it writes the marker). An interface without a description is
// someone else's, whatever its name is.

func (l *Local) ifOpts() ifconfig.Options { return ifconfig.Options{} }

func (l *Local) ifReader(name string) (ifconfig.Reader, error) {
	rd, ok := l.d.Net.(ifconfig.Reader)
	if !ok {
		return nil, forbidden("interface %q: the helper cannot read interfaces here, so it changes none", name)
	}
	return rd, nil
}

// ifOwned checks, in the host's network stack, that JailOps owns name.
func (l *Local) ifOwned(ctx context.Context, name string) error {
	if err := ifconfig.ValidateIfName(name); err != nil {
		return err
	}
	rd, err := l.ifReader(name)
	if err != nil {
		return err
	}
	i, err := rd.Show(ctx, name)
	if err != nil {
		return err
	}
	return l.ifOpts().Owns(i)
}

// ifsOwned is ifOwned for several names, all validated before any is read.
func (l *Local) ifsOwned(ctx context.Context, names ...string) error {
	for _, n := range names {
		if err := ifconfig.ValidateIfName(n); err != nil {
			return err
		}
	}
	for _, n := range names {
		if err := l.ifOwned(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// ifOwnedInJail checks that JailOps owns name in the vnet of jail (a managed jail; the caller checks that). Root in a
// vnet jail can set the descriptions of the interfaces in its own vnet, so inside a jail the marker proves less than
// on the host: it keeps the helper off the jail's loopback and off an interface of the host's stack when the jail has
// none of its own, and what the jail could forge there is an interface of its own vnet.
func (l *Local) ifOwnedInJail(ctx context.Context, jail, name string) error {
	if err := ifconfig.ValidateIfName(name); err != nil {
		return err
	}
	rd, err := l.ifReader(name)
	if err != nil {
		return err
	}
	i, err := rd.ShowInJail(ctx, jail, name)
	if err != nil {
		return err
	}
	return l.ifOpts().Owns(i)
}

// ifCreatable checks a name the helper is asked to create: not a driver's (ifconfig.CheckNewName) and not taken. A
// name JailOps already owns answers already_exists (creating is idempotent for the caller); a name taken by anything
// else is refused, because the helper never takes over an interface by its name.
func (l *Local) ifCreatable(ctx context.Context, name string) error {
	if err := ifconfig.CheckNewName(name); err != nil {
		return err
	}
	rd, err := l.ifReader(name)
	if err != nil {
		return err
	}
	i, err := rd.Show(ctx, name)
	switch {
	case api.IsCode(err, api.CodeNotFound):
		return nil
	case err != nil:
		return err
	}
	if err := l.ifOpts().Owns(i); err != nil {
		return forbidden("interface %q exists and is not JailOps's; the helper never takes over an interface by its name (%v)", name, err)
	}
	return api.Errorf(api.CodeAlreadyExists, "interface %s already exists", name)
}
