package engine

import (
	"encoding/json"
	"fmt"

	"github.com/go-logr/logr"
	kyvernov1 "github.com/kyverno/kyverno/api/kyverno/v1"
	kyvernov2alpha1 "github.com/kyverno/kyverno/api/kyverno/v2alpha1"
	engineapi "github.com/kyverno/kyverno/pkg/engine/api"
	"github.com/kyverno/kyverno/pkg/engine/internal"
	matched "github.com/kyverno/kyverno/pkg/utils/match"
	stringutils "github.com/kyverno/kyverno/pkg/utils/strings"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

func findExceptions(
	selector engineapi.PolicyExceptionSelector,
	policy kyvernov1.PolicyInterface,
	rule string,
) ([]*kyvernov2alpha1.PolicyException, error) {
	if selector == nil {
		return nil, nil
	}
	polexs, err := selector.List(labels.Everything())
	if err != nil {
		return nil, err
	}
	var result []*kyvernov2alpha1.PolicyException
	policyName, err := cache.MetaNamespaceKeyFunc(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to compute policy key: %w", err)
	}
	for _, polex := range polexs {
		if polex.Contains(policyName, rule) {
			result = append(result, polex)
		}
	}
	return result, nil
}

// matchesException checks if an exception applies to the resource being admitted
func matchesException(
	e *engine,
	selector engineapi.PolicyExceptionSelector,
	logger logr.Logger,
	policyContext engineapi.PolicyContext,
	rule kyvernov1.Rule,
) (*kyvernov2alpha1.PolicyException, error) {
	fmt.Println("PolicyContext")
	p, err2 := json.Marshal(policyContext)
	if err2 != nil {
		fmt.Println(err2)
	}
	fmt.Println(string(p))
	candidates, err := findExceptions(selector, policyContext.Policy(), rule.Name)
	fmt.Println("Candidates")
	c, err1 := json.Marshal(candidates)
	if err1 != nil {
		fmt.Println(err1)
	}
	fmt.Println(string(c))
	if err != nil {
		return nil, err
	}
	gvk, subresource := policyContext.ResourceKind()
	fmt.Println("subresource")
	fmt.Println(subresource)
	resource := policyContext.NewResource()
	fmt.Println("newresource")
	fmt.Println(resource)

	if resource.Object == nil {
		fmt.Println("oldresource")
		resource = policyContext.OldResource()
		fmt.Println(resource)
	}

	for _, candidate := range candidates {
		err := matched.CheckMatchesResources(
			resource,
			candidate.Spec.Match,
			policyContext.NamespaceLabels(),
			policyContext.AdmissionInfo(),
			gvk,
			subresource,
		)
		exception, _ := conditionsException(e.exceptionSelector, logger, policyContext, rule)
		// if there's no error it means a match
		if err == nil && exception != nil {
			return candidate, nil
		}
	}
	return nil, nil
}

func conditionsException(
	selector engineapi.PolicyExceptionSelector,
	logger logr.Logger,
	policyContext engineapi.PolicyContext,
	rule kyvernov1.Rule,
) (*kyvernov2alpha1.PolicyException, error) {
	candidates, err := findExceptions(selector, policyContext.Policy(), rule.Name)
	if err != nil {
		return nil, err
	}
	resource := policyContext.NewResource()
	if resource.Object == nil {
		resource = policyContext.OldResource()
	}
	for _, candidate := range candidates {
		preconditionsPassed, msg, err := internal.CheckPreconditions(logger, policyContext.JSONContext(), candidate.Spec.GetAnyAllConditions())
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate preconditions:%w", err)
		}
		if !preconditionsPassed {
			s := stringutils.JoinNonEmpty([]string{"preconditions not met", msg}, "; ")
			return nil, fmt.Errorf(s)
		}
		// if there's no error it means a match
		if err == nil {
			return candidate, nil
		}
	}
	return nil, nil
}

// hasPolicyExceptions returns nil when there are no matching exceptions.
// A rule response is returned when an exception is matched, or there is an error.
func (e *engine) hasPolicyExceptions(
	logger logr.Logger,
	ruleType engineapi.RuleType,
	ctx engineapi.PolicyContext,
	rule kyvernov1.Rule,
) *engineapi.RuleResponse {
	// if matches, check if there is a corresponding policy exception
	exception, err := matchesException(e, e.exceptionSelector, logger, ctx, rule)
	if err != nil {
		logger.Error(err, "failed to match exceptions")
		return nil
	}
	if exception == nil {
		return nil
	}
	key, err := cache.MetaNamespaceKeyFunc(exception)
	if err != nil {
		logger.Error(err, "failed to compute policy exception key", "namespace", exception.GetNamespace(), "name", exception.GetName())
		return engineapi.RuleError(rule.Name, ruleType, "failed to compute exception key", err)
	} else {
		logger.V(3).Info("policy rule skipped due to policy exception", "exception", key)
		return engineapi.RuleSkip(rule.Name, ruleType, "rule skipped due to policy exception "+key).WithException(exception)
	}
}
