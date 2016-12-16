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

try:
    import jinja2
except ImportError:
    raise Exception('Please install jinja2')

PRODUCTS = {
    'auth': {
        'tarball_name': 'pdns',
        'rootdir': '',
        'configure': '--without-modules --without-dynmodules '
                     '--disable-depedency-tracking'
    },
    'recursor': {
        'tarball_name': 'pdns-recursor',
        'rootdir': 'pdns/recursordist',
        'configure': '--disable-depedency-tracking'
    },
    'dnsdist': {
        'tarball_name': 'dnsdist',
        'rootdir': 'pdns/dnsdistdist',
        'configure': '--disable-depedency-tracking',
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

class pdns_builder:
    def __init__(self, version, dockersocketpath, destdir):
        self.config = {}
        self.config['rootdir'] = os.path.realpath(
            os.path.join(os.path.dirname(__file__), '..'))
        self.config['version'] = version
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

    def _move_files(self, files):
        os.makedirs(self.config['destdir'], exist_ok=True)

        if type(files != list):
            files = [files]

        for f in files:
            shutil.move(f, self.config['destdir'])

    def generate_tarball(self, product):
        tmpdir = os.path.join(tempfile.mkdtemp(), 'build')
        print(self.config.get('rootdir'))
        shutil.copytree(self.config.get('rootdir'), tmpdir)
        workdir = os.path.join(tmpdir, PRODUCTS[product]['rootdir'])

        try:
            subprocess.check_output(
                ['autoreconf', '-i'],
                cwd=workdir,
                env={'PDNS_BUILD_NUMBER': os.environ.get(
                        'PDNS_BUILD_NUMBER', ''),
                     'IS_RELEASE': self.config.get('is_release', 'NO')},
                stderr=subprocess.STDOUT)
            subprocess.check_output(
                ['./configure', '{}'.format(PRODUCTS[product]['configure'])],
                cwd=workdir,
                stderr=subprocess.STDOUT)
            subprocess.check_output(
                ['make', 'dist'],
                cwd=workdir,
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise Exception('Problem while creating tarball:\n{}'.format(
                e.output.decode()))

        files = glob.glob(workdir + '/*.tar.bz2')
        self._move_files(files)

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
                   '--version', version,
                   '--move-to', retrieve_path]
        self._docker_run(image, command, volumes, binds, retrieve_path,
                         retrieve_file)

    def build_rpm(self, product, pkg_release='1pdns%{dist}'):
        self.generate_tarball(product)
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

    def build_pkgs(self, docker, product, distro=None, distro_release=None):
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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="build-pkg",
        description="Package builder script for the PowerDNS software")

    subparsers = parser.add_subparsers(dest='selected_mode')

    build_parser = subparsers.add_parser(
        'build-pkg', help='Build packages for different distributions')
    build_parser.add_argument(
        'program', metavar=('PROGRAM'), choices=PRODUCTS.keys(),
        help='Build one of these programs: %(choices)s')
    build_parser.add_argument(
        '--docker', nargs=2, metavar=('DISTRO', 'RELEASE'),
        help='Build the packages inside a docker container')
    build_parser.add_argument(
        '--docker-socket', nargs=1, metavar=('URI'),
        default='unix:///var/run/docker.sock',
        help='The URI for the docker socket.')
    build_parser.add_argument(
        '--move-to', nargs=1, metavar=('PATH'), default=os.getcwd(),
        help='Move created packages to this directory')
    versioning = build_parser.add_mutually_exclusive_group()
    versioning.add_argument(
        '--is-release', action='store_true',
        help='Set to generate the version number based on the git tag')
    versioning.add_argument(
        '--version',
        help="Set the version number explicitly")

    mydir = os.path.realpath(
        os.path.join(
            os.path.dirname(__file__),
            '..'))
    args = parser.parse_args()

    if vars(args)['selected_mode'] == 'build-pkg':
        version = vars(args).get('version', None)
        if not version:
            is_release = 'YES' if vars(args).get('is_release', None) else 'NO'
            version = subprocess.check_output(
                [os.path.join(mydir, 'build-aux', 'gen-version')],
                env={'PDNS_BUILD_NUMBER': os.environ.get('PDNS_BUILD_NUMBER',
                                                         ''),
                     'IS_RELEASE': is_release}
                ).decode('utf-8')
        a = pdns_builder(version, args.docker_socket, args.move_to)

        product = args.program
        docker = True if args.docker else False
        distro = args.docker[0].lower() if docker else None
        distro_release = args.docker[1].lower() if docker else None

        try:
            a.build_pkgs(docker, product, distro, distro_release)
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            print(''.join('!! ' + line for line in traceback.format_exception(
                exc_type, exc_value, exc_traceback)))
            sys.exit(1)
        sys.exit(0)

    parser.print_help()
    sys.exit(0)
