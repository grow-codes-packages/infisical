package codes.grow.packages.infisical;

import static org.assertj.core.api.Assertions.assertThat;

import codes.grow.packages.infisical.secrets.EnvLoader;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Exercises every option builder: null and real values for each setter, every getter. */
class OptionsTest {
  static final List<Class<?>> OPTIONS =
      List.of(
          ListSecretsOptions.class,
          GetSecretOptions.class,
          CreateSecretOptions.class,
          UpdateSecretOptions.class,
          DeleteSecretOptions.class,
          SecretInput.class,
          SecretUpdate.class,
          BatchScope.class,
          UpdateSecretsOptions.class,
          DeleteSecretsOptions.class,
          ListFoldersOptions.class,
          CreateFolderOptions.class,
          UpdateFolderOptions.class,
          DeleteFolderOptions.class,
          ListProjectsOptions.class,
          ProjectOptions.class,
          CreateEnvironmentOptions.class,
          SecretImportOptions.class,
          CreateSecretImportOptions.class,
          ListSecretVersionsOptions.class,
          EnvOptions.class,
          SecretsProviderOptions.class);

  static Object sample(Class<?> type) {
    if (type == String.class) {
      return "x";
    }
    if (type == boolean.class || type == Boolean.class) {
      return Boolean.TRUE;
    }
    if (type == int.class) {
      return 7;
    }
    if (type == List.class) {
      return List.of("a");
    }
    if (type == Map.class) {
      return Map.of("k", "v");
    }
    if (type == SecretType.class) {
      return SecretType.PERSONAL;
    }
    if (type == BatchUpdateMode.class) {
      return BatchUpdateMode.UPSERT;
    }
    if (type == EnvLoader.Target.class) {
      return EnvLoader.map(new java.util.HashMap<>());
    }
    throw new IllegalArgumentException(type.getName());
  }

  static Object build(Class<?> options, boolean nulls) throws Exception {
    Object b = options.getMethod("builder").invoke(null);
    for (Method m : b.getClass().getMethods()) {
      if (m.getDeclaringClass() != b.getClass() || m.getParameterCount() != 1) {
        continue;
      }
      Class<?> p = m.getParameterTypes()[0];
      m.invoke(b, nulls && !p.isPrimitive() ? null : sample(p));
    }
    return b.getClass().getMethod("build").invoke(b);
  }

  @Test
  void everyBuilderAndGetter() throws Exception {
    for (Class<?> c : OPTIONS) {
      Object defaults = c.getMethod("defaults").invoke(null);
      Object full = build(c, false);
      Object nulls = build(c, true);
      for (Method g : c.getDeclaredMethods()) {
        if (!Modifier.isPublic(g.getModifiers())
            || Modifier.isStatic(g.getModifiers())
            || g.getParameterCount() != 0) {
          continue;
        }
        Object d = g.invoke(defaults);
        Object f = g.invoke(full);
        g.invoke(nulls);
        assertThat(f).as(c.getSimpleName() + "." + g.getName()).isNotNull();
        if (f instanceof Optional) {
          assertThat((Optional<?>) f).as(c.getSimpleName() + "." + g.getName()).isPresent();
        }
        assertThat(d).as(c.getSimpleName() + "." + g.getName() + " default").isNotNull();
      }
    }
  }

  @Test
  void defaultsMatchTheSpec() {
    assertThat(ListSecretsOptions.defaults().expandReferences()).isTrue();
    assertThat(ListSecretsOptions.defaults().includeImports()).isTrue();
    assertThat(ListSecretsOptions.defaults().viewSecretValue()).isTrue();
    assertThat(ListSecretsOptions.defaults().recursive()).isFalse();
    assertThat(ListSecretVersionsOptions.defaults().limit()).isEqualTo(20);
    assertThat(UpdateSecretOptions.defaults().value()).isEmpty();
    assertThat(UpdateSecretOptions.defaults().tagIds()).isEmpty();
    assertThat(SecretInput.of("K", "v").key()).isEqualTo("K");
    assertThat(SecretUpdate.of("K", "v").value()).contains("v");
    assertThat(EnvOptions.defaults().target()).isNotNull();
  }
}
