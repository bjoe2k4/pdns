#!/usr/bin/env python3

from io import BytesIO
import glob
import os.path
import platform
import shutil
import subprocess
import sys
import traceback
import tempfile
import json
import logging
import tarfile


try:
    import jinja2
except ImportError:
    raise Exception('Please install jinja2')

PRODUCTS = {
    'pdns': {
        'tarball_name': 'pdns',
        'rootdir': '',
        'tar_configure': ['--without-modules', '--without-dynmodules',
                          '--enable-tools', '--disable-depedency-tracking']
    },
    'recursor': {
        'tarball_name': 'pdns-recursor',
        'rootdir': 'pdns/recursordist',
        'tar_configure': ['--disable-depedency-tracking']
    },
    'dnsdist': {
        'tarball_name': 'dnsdist',
        'rootdir': 'pdns/dnsdistdist',
        'tar_configure': ['--disable-depedency-tracking'],
        'dependencies': {
            'centos': {
                'all': ['boost-devel', 'lua-devel', 'protobuf-compiler',
                        'protobuf-devel', 're2-devel', 'readline-devel',
                        'libedit-devel'],
                '7': ['systemd', 'systemd-devel', 'libsodium-devel']
            }
        }
    }
}

OS = {
    'debian': {
        'jessie': {
            'deps': [],
            'pdns': {
                'backends': [],
                'deps': [],
                'configure': []
            },
            'recursor': {
                'deps': [],
                'configure': []
            },
            'dnsdist': {
                'deps': [],
                'configure': []
            }
        }
    },
    'centos': {
        '6': {
            'deps': [],
            'pdns': {
                'backends': [],
                'deps': [],
                'configure': []
            },
            'recursor': {
                'deps': [],
                'configure': []
            },
            'dnsdist': {
                'deps': [],
                'configure': []
            }
        },
        '7': {
            'deps': [],
            'pdns': {
                'backends': [],
                'deps': [],
                'configure': []
            },
            'recursor': {
                'deps': [],
                'configure': []
            },
            'dnsdist': {
                'deps': [],
                'configure': []
            }
        }
    }
}

class pdns_builder:
    def __init__(self, dockersocketpath, destdir):
        self.config = {}
        self.config['rootdir'] = os.path.realpath(
            os.path.join(os.path.dirname(__file__), '..'))
        self.config['dockersocketpath'] = dockersocketpath
        self.config['destdir'] = destdir
        self.dockerclient = None

    def _create_docker_client(self):
        if self.dockerclient:
            return

        try:
            import docker
        except ImportError:
            raise Exception('Please install docker-py')

        self.dockerclient = docker.Client(base_url=self.config['dockersocketpath'])

    def _docker_build(self, dockerfile, image):
        self._create_docker_client()

        f = BytesIO(dockerfile.encode('utf8'))
        resp = [x.decode() for x in self.dockerclient.build(fileobj=f, rm=True,
                                                   tag=image)]
        resp = [json.loads(e).get('stream', '') for e in resp]
        if not resp[-1].startswith('Successfully built'):
            raise Exception('Error while creating docker image:\n{}'.format(
                ''.join(resp)))

    def _docker_run(self, image, command, volumes=None, binds=None,
                    retrieve_path=None, retrieve_file=None):
        self._create_docker_client()

        if not ((volumes and binds) or (not volumes and not binds)):
            raise ValueError('binds and volumes must both be None or both'
                             'have a value')

        if not binds:
            container = self.dockerclient.create_container(
                    image=image,
                    command=command)
        else:
            container = self.dockerclient.create_container(
               image=image,
               volumes=volumes,
               host_config=self.dockerclient.create_host_config(binds=binds),
               command=command)

        self.dockerclient.start(container)
        exitcode = self.dockerclient.wait(container)
        if exitcode > 0:
            msg = 'Build failure:\n{}'.format(
                self.dockerclient.logs(container).decode())
            self.dockerclient.remove_container(container)
            raise Exception(msg)

        if retrieve_path and retrieve_file:
            stream, _ = self.dockerclient.get_archive(container, retrieve_path)
            if not stream:
                self.dockerclient.remove_container(container)
                raise Exception('Unable to retrieve path "{}"'.format(
                    retrieve_path))

            with open(retrieve_file, 'wb') as f:
                for d in stream:
                    f.write(d)

        self.dockerclient.remove_container(container)

    def _move_files(self, files, dest=None):
        os.makedirs(self.config['destdir'], exist_ok=True)

        if type(files) != list:
            files = [files]

        if dest == None:
            dest = self.config['destdir']

        for f in files:
            shutil.move(f, dest)


    def build_with_docker(self, product, distro, distro_release):
        builddeps = PRODUCTS[product]['dependencies'][distro]['all']
        builddeps.extend(PRODUCTS[product]['dependencies'][distro].get(distro_release, []))
        builddeps = ' '.join(builddeps)

        template_name = '{}.j2'.format(distro)

        dockerfile = jinja2.Environment(
            loader=jinja2.FileSystemLoader('build-scripts/dockerfiles')
                ).get_template(template_name).render(
                        {'distro': distro,
                         'distro_release': distro_release,
                         'builddeps': builddeps})

        image = 'pdns-{}-builder:{}-{}'.format(
            product,
            distro,
            distro_release)
        self._docker_build(dockerfile, image)

        this_dir = os.path.realpath(
            os.path.join(os.path.dirname(__file__), '..'))

        binds = [this_dir + ':' + '/build' + ':ro']
        volumes = [this_dir]

        retrieve_path = '/root/rpmbuild/{}'.format(product)
        retrieve_file = os.path.join(
            self.config['destdir'], '{}-{}-{}-{}.tar'.format(
                PRODUCTS[product]['tarball_name'],
                self.config['version'],
                distro,
                distro_release))

        command = ['/build/build-scripts/build-pkg.py',
                   'build-pkg', product,
                   '--tarball-path', os.path.join(
                        '/build', os.path.split(self.config['tarball'])[-1]),
                   '--move-to', retrieve_path]
        self._docker_run(image, command, volumes, binds, retrieve_path,
                         retrieve_file)

    def build_rpm(self, product, pkg_release='1pdns%{dist}'):
        subprocess.call(['rpmdev-setuptree'])
        rpmbuilddir = os.path.join(os.path.expanduser('~'), 'rpmbuild')
        sourcesdir = os.path.join(rpmbuilddir, 'SOURCES')
        self._move_files(self.config.get('tarball'), sourcesdir)
        specfile = os.path.join(rpmbuilddir, 'SPECS',
                                '{}.spec'.format(product))
        rpmdir = os.path.join(rpmbuilddir, 'RPMS', 'x86_64')
        t = jinja2.Environment(
            loader=jinja2.FileSystemLoader('build-scripts')).get_template(
                '{}.spec.j2'.format(product)).render({
                    'pkg_version': self.config['version'],
                    'pkg_release': pkg_release
                    })
        with open(specfile, 'w') as f:
            f.write(t)
        try:
            subprocess.check_output(['rpmbuild', '-bb', specfile],
                                    shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise Exception('Problem while building RPM:\n{}'.format(
                e.output.decode()))

        files = glob.glob(rpmdir + '/{}*{}*.rpm'.format(
            PRODUCTS[product]['tarball_name'],
            self.config['version']))
        self._move_files(files)

    def build_pkgs(self, docker, product, tarball=None, distro=None,
                   distro_release=None):
        self.config['tarball'] = tarball
        if docker:
            self.build_with_docker(product, distro, distro_release)
            return

        self.distro, self.distro_release, _ = platform.dist()
        if self.distro in ['centos', 'redhat']:
            self.build_rpm(product)
            return
        if self.distro in ['debian', 'ubuntu']:
            self.build_deb(product)
            return
        print("Unknown distribution: " + self.distro)
        return

class pdns_tar_builder(pdns_builder):
    def generate_tarball_with_docker(self, product, is_release):
        builddeps = 'automake autoconf bison build-essential curl flex git ragel pandoc'

        dockerfile = jinja2.Environment(
            loader=jinja2.FileSystemLoader('build-scripts/dockerfiles')
                ).get_template('tarball-builder').render()
        image = 'pdns-tar-builder'
        self._docker_build(dockerfile, image)

        this_dir = os.path.realpath(
            os.path.join(os.path.dirname(__file__), '..'))

        retrieve_path = '/{}'.format(product)
        retrieve_file = os.path.join(
            self.config['destdir'], '{}.tar'.format(
                PRODUCTS[product]['tarball_name']))

        binds = [this_dir + ':' + '/build' + ':ro']
        volumes = [this_dir]

        command = ['/build/build-scripts/build-pkg.py',
                   'generate-tarball', product,
                   '--move-to', retrieve_path]
        if is_release:
            command + ['--is-release']
        self._docker_run(image, command, volumes, binds, retrieve_path,
                         retrieve_file)
        f = tarfile.open(retrieve_file)
        for member in f.members():
            f.extract(member, path=self.config['destdir'])

    def generate_tarball_locally(self, product, is_release):
        # Copy to a temp dir to ensure the repo is not polluted
        tmpdir = os.path.join(tempfile.mkdtemp(), 'build')
        try:
            shutil.copytree(self.config.get('rootdir'), tmpdir, symlinks=True)
        except:
            pass

        workdir = os.path.join(tmpdir, PRODUCTS[product]['rootdir'])
        try:
            os.remove(os.path.join(workdir, '.version'))
        except OSError:
            pass

        logging.warning('Starting tarball generation in {}'.format(workdir))
        try:
            subprocess.check_output(
                ['git', 'clean', '-Xf'],
                cwd=workdir,
                stderr=subprocess.STDOUT)
            subprocess.check_output(
                ['autoreconf', '-i'],
                cwd=workdir,
                env={'PDNS_BUILD_NUMBER': os.environ.get(
                        'PDNS_BUILD_NUMBER', ''),
                     'IS_RELEASE': self.config.get('is_release', 'NO')},
                stderr=subprocess.STDOUT)
            subprocess.check_output(
                ['./configure'] + PRODUCTS[product]['tar_configure'],
                cwd=workdir,
                stderr=subprocess.STDOUT)
            subprocess.check_output(
                ['make', 'dist'],
                cwd=workdir,
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            # cleanup
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise Exception('Problem while creating tarball - command "{}" '
                            'failed\n{}'.format(' '.join(e.cmd),
                                                e.output.decode()))
        except:
            # cleanup
            shutil.rmtree(tmpdir, ignore_errors=True)
            raise

        with open('.version') as f:
            version = f.readline().strip()

        tarball = os.path.join(workdir,
            '{}-{}.tar.bz2'.format(PRODUCTS[product]['tarball_name'], version))
        self._move_files(tarball)
        shutil.rmtree(tmpdir, ignore_errors=True)

    def generate_tarball(self, product, is_release, docker):
        if docker:
            self.generate_tarball_with_docker(product, is_release)
            return
        self.generate_tarball_locally(product, is_release)
        return


def gen_version(is_release=None):
    mydir = os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
    is_release = 'YES' if is_release else 'NO'
    version = subprocess.check_output(
        [os.path.join(mydir, 'build-aux', 'gen-version')],
        env={'PDNS_BUILD_NUMBER': os.environ.get('PDNS_BUILD_NUMBER', ''),
             'IS_RELEASE': is_release}
        ).decode('utf-8')

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="build-pkg",
        description="Package builder script for the PowerDNS software")

    parser.add_argument(
        '--docker-socket', nargs=1, metavar=('URI'),
        default='unix:///var/run/docker.sock',
        help='The URI for the docker socket.')
    parser.add_argument(
        '--move-to', nargs=1, metavar=('PATH'), default=[os.getcwd()],
        help='Move created artifacts to this directory')

    subparsers = parser.add_subparsers(dest='selected_mode')

    build_parser = subparsers.add_parser(
        'build-pkg', help='Build packages for different distributions')
    build_parser.add_argument(
        '--docker', nargs=2, metavar=('DISTRO', 'RELEASE'),
        help='Build inside a container for DISTRO and RELEASE')
    build_parser.add_argument(
        'tarball', metavar='TARBALL', help='Build from this tarball')

    tarball_parser = subparsers.add_parser(
        'generate-tarball', help='Generate a tarball')
    tarball_parser.add_argument(
        'product', metavar=('PRODUCT'), choices=PRODUCTS.keys(),
        help='Build one of these programs: %(choices)s')
    tarball_parser.add_argument(
        '--is-release', action='store_true',
        help='Set to generate the version number based on the git tag')
    tarball_parser.add_argument(
        '--docker', action='store_true',
        help='Generate the tarball inside docker')

    args = parser.parse_args()

    selected_mode = vars(args)['selected_mode']

    if selected_mode == 'generate-tarball':
        builder = pdns_tar_builder(args.docker_socket, args.move_to[0])

        v = vars(args).get('version', None)
        ir = vars(args).get('is_release', None)
        version = gen_version(ir)
        docker = True if args.docker else False
        is_release = True if args.is_release else False

        builder.generate_tarball(args.product, is_release, docker)
        sys.exit(0)

    if selected_mode == 'build-pkg':
        builder = pdns_builder(version, args.docker_socket, args.move_to[0])

        docker = True if args.docker else False
        distro = args.docker[0].lower() if docker else None
        distro_release = args.docker[1].lower() if docker else None
        product = args.program

        only_tarball = True if args.generate_tarball else False
        tarball_path = vars(args).get('use_tarball', None)

        try:
            if not tarball_path:
                builder.generate_tarball(docker, product)
                tarball_path = os.path.join(args.move_to[0],
                    '{}-{}.tar.bz2'.format(PRODUCTS[product]['tarball_name'],
                                           version))
            if only_tarball:
                sys.exit(0)
            builder.build_pkgs(docker, product, tarball_path, distro,
                distro_release)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(''.join('!! ' + line for line in traceback.format_exception(
                exc_type, exc_value, exc_traceback)))
            sys.exit(1)
        sys.exit(0)

    parser.print_help()
    sys.exit(0)
