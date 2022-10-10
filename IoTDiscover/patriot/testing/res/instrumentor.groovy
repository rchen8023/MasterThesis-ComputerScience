import org.codehaus.groovy.transform.GroovyASTTransformationClass
import org.codehaus.groovy.transform.GroovyASTTransformation
import org.codehaus.groovy.transform.ASTTransformation
import org.codehaus.groovy.control.CompilerConfiguration
import org.codehaus.groovy.control.CompilePhase
import org.codehaus.groovy.control.SourceUnit
import org.codehaus.groovy.control.customizers.ASTTransformationCustomizer
import org.codehaus.groovy.ast.*
import org.codehaus.groovy.syntax.Token
import groovy.inspect.swingui.AstNodeToScriptVisitor
import groovy.io.FileType
import java.lang.annotation.Retention
import java.lang.annotation.RetentionPolicy
import java.lang.annotation.Target
import java.lang.annotation.ElementType
import java.io.StringWriter
import org.codehaus.groovy.transform.*
import org.codehaus.groovy.control.*
import org.codehaus.groovy.ast.expr.*
import org.codehaus.groovy.ast.stmt.*
import org.codehaus.groovy.ast.*

@Retention(RetentionPolicy.SOURCE)
@Target([ElementType.TYPE])
@GroovyASTTransformationClass(classes = [ASTExplorer])
@interface AST { }

@GroovyASTTransformation(phase = CompilePhase.CANONICALIZATION)
class ASTExplorer implements ASTTransformation {
  public void visit(ASTNode[] nodes, SourceUnit sourceUnit) {
    println("\t\tApplying AST transformation...")
    ModuleNode ast = sourceUnit.getAST();
    def astClassNode = ast.getClasses()[0]
    def appName = astClassNode.getField("smartApp").initialValueExpression.getText()
    def actionList = astClassNode.getField("actionList").initialValueExpression.getText()
    def header = astClassNode.getField("header").initialValueExpression.getText()
    List<MethodNode> methods = astClassNode.getMethods()
    for (MethodNode methodNode : methods) {
      def params = methodNode.getParameters()
      methodNode.getCode().visit(new ExpressionTransformer(sourceUnit, params, actionList));
    }
    astWriter(ast, appName, header)
  }
  def astWriter(ast, myAppName, header) {
    File file = new File(myAppName)
    StringWriter writer = new StringWriter();
    AstNodeToScriptVisitor visitor = new AstNodeToScriptVisitor(writer);
    for (MethodNode method : ast.getClasses()[0].getMethods()) {
      if (method.getName() != 'main') {
        visitor.visitMethod(method);
      }
    }
    def modifiedContent = writer.toString().replaceAll('public java.lang.Object', 'def')
    modifiedContent = modifiedContent.replaceAll(/java.lang.Object\s*.*\s*=/) { m -> "def ${m}" }
    modifiedContent = modifiedContent.replaceAll('java.lang.Object ', '')
    modifiedContent = modifiedContent.replaceAll('java.lang.Integer', 'int')
    modifiedContent = modifiedContent.replaceAll('java.math.BigInteger', 'BigInteger')
    modifiedContent = modifiedContent.replaceAll('java.lang.String', 'String')
    modifiedContent = modifiedContent.replaceAll('this\\.', '')
    file.write(header + modifiedContent)
    println("\t\tInstrumentation is done!\n")
  }
}

class ExpressionTransformer extends ClassCodeExpressionTransformer {
  SourceUnit sourceUnit
  Parameter[] params
  String actionList
  def actions = [:]
  ExpressionTransformer(SourceUnit sourceUnit, Parameter[] params, String actionList) {
    this.sourceUnit = sourceUnit
    this.params = params
    this.actionList = actionList
    load_actions(this.actionList)
  }

  @Override
  protected SourceUnit getSourceUnit() {
    return sourceUnit;
  }

  @Override
  public Expression transform(Expression exp) {
    if (exp instanceof MethodCallExpression) {
      if (actions.containsKey(exp.methodAsString)) {

        def args = new TupleExpression()
        args.addExpression(new MethodCallExpression(new VariableExpression("app"),
                           new ConstantExpression("getLabel"),
                           new ArgumentListExpression()))
        if (params) {
          def evtArg = new ArgumentListExpression(params)
          args.addExpression(evtArg.flatten())
        }
        else {
          args.addExpression(ConstantExpression.NULL)
        }
        if ("${exp.getObjectExpression()}" != "${new VariableExpression("this")}") {
          args.addExpression(new MethodCallExpression(new VariableExpression(exp.getObjectExpression()),
                             new ConstantExpression("getDisplayName"),
                             new ArgumentListExpression()))
        }
        else {
          args.addExpression(ConstantExpression.NULL)
        }
        args.addExpression(new ConstantExpression(actions.get(exp.methodAsString)))
        def argExpressions = exp.arguments.getExpressions()
        if (argExpressions) {
          // for (Expression expression : argExpressions) {
          //   args.addExpression(expression)
          // }
          args.addExpression(argExpressions[0])
        }
        else {
          args.addExpression(ConstantExpression.NULL)
        }
        def policyCheckerCallExpression =
        new MethodCallExpression(new VariableExpression("parent"),
        new ConstantExpression("verify"),
        args)
        def logDebugCallExpression =
        new MethodCallExpression (new VariableExpression("log"),
        new ConstantExpression("debug"),
        new ConstantExpression("Invariants Violation!"))

        BooleanExpression bexpression =
        new BooleanExpression(new BinaryExpression(policyCheckerCallExpression,
          Token.newSymbol("==", 0, 0),
          new ConstantExpression(true)));

          return new TernaryExpression(bexpression, exp, logDebugCallExpression)
        }
      }

      Expression newExpr = super.transform(exp);
      if (newExpr != null) {
        newExpr.visit(this)
      }
      return newExpr
    }
  def load_actions(actionListFileName) {
    new File(actionListFileName).eachLine { line ->
                                                  def pair = line.trim().split(',')
                                                  actions.put(pair[0].trim(), pair[1].trim())
                                          }
  }
}

//==================================================================

if (args.size() == 3) {
  println("")
  String actionListFileName = args[0]
  String sourceFolder = args[1]
  String destFolder = args[2]
  def inst_dir = new File(destFolder)
  inst_dir.mkdir()
  def dir = new File(sourceFolder)
  dir.eachFileRecurse (FileType.FILES) {
    if(it.name.endsWith('.groovy')) {
      String smartapp = it.text
      String instrumentedSmartApp = destFolder + '/' + it.name
      def sections = smartapp.split('def installed')
      String header = sections[0]
      String body = 'def installed' + sections[1]
      String wrapper_class = """class WrapperClass {
        String smartApp = "${instrumentedSmartApp}"
        String actionList = "${actionListFileName}"
        String header ='''${header}'''
        static void main(String[] args){}
          ${body}
        }"""
      println("\tTarget Program: ${it.name}")
      def configuration = new CompilerConfiguration()
      configuration.addCompilationCustomizers(new ASTTransformationCustomizer(AST))
      def shell = new GroovyShell(configuration)
      println("\t\tStarting istrumentation...")
      try {
        shell.evaluate(wrapper_class)
      } catch (Exception ex) {
        println("\t\tException occured:")
        println("\t\t" + ex.toString())
      }
    }
  }
}
